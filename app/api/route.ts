import { neon } from '@neondatabase/serverless'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { randomBytes } from 'node:crypto'
import type { NextRequest } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const sql = neon(process.env.DATABASE_URL!)

type Me = { id: number; u: string }

const FONTS = ['sans', 'serif', 'mono', 'round']
const FS_MIN = 14
const FS_MAX = 22
const AVATAR_COUNT = 6

// JWT_SECRET is optional: without it, a random secret is generated once and stored in the database.
let ready: Promise<string> | undefined
const init = () =>
  ready ||
  (ready = (async () => {
    await sql`create table if not exists users(id serial primary key, username text unique not null, hash text not null, bio text default '', created timestamptz default now())`
    await sql`create table if not exists posts(id serial primary key, uid int not null references users(id) on delete cascade, body text default '', img text, created timestamptz default now())`
    await sql`create table if not exists reacts(pid int not null references posts(id) on delete cascade, uid int not null references users(id) on delete cascade, v int not null, primary key(pid, uid))`
    await sql`create table if not exists comments(id serial primary key, pid int not null references posts(id) on delete cascade, uid int not null references users(id) on delete cascade, body text not null, created timestamptz default now())`
    await sql`create index if not exists posts_uid_idx on posts(uid)`
    await sql`create index if not exists comments_pid_idx on comments(pid)`
    await sql`alter table users add column if not exists av int not null default 0`
    await sql`alter table posts add column if not exists font text not null default 'sans'`
    await sql`alter table posts add column if not exists fs int not null default 16`
    if (process.env.JWT_SECRET) return process.env.JWT_SECRET
    await sql`create table if not exists app_config(k text primary key, v text not null)`
    await sql`insert into app_config(k, v) values('jwt_secret', ${randomBytes(48).toString('hex')}) on conflict (k) do nothing`
    const [row] = await sql`select v from app_config where k='jwt_secret'`
    return row.v as string
  })().catch((e) => {
    ready = undefined
    throw e
  }))

const out = (d: unknown, status = 200) => Response.json(d, { status })

export async function GET(req: NextRequest) {
  try {
    const p = req.nextUrl.searchParams
    if (p.get('a') !== 'img') return out({ e: 'Bilinmeyen işlem' }, 400)
    const [r] = await sql`select img from posts where id=${Number(p.get('id')) || 0}`
    const m = r?.img && String(r.img).match(/^data:(image\/\w+);base64,(.*)$/)
    if (!m) return new Response(null, { status: 404 })
    return new Response(Buffer.from(m[2], 'base64'), {
      headers: { 'Content-Type': m[1], 'Cache-Control': 'public, max-age=31536000, immutable' },
    })
  } catch (e) {
    console.error(e)
    return new Response(null, { status: 500 })
  }
}

export async function POST(req: NextRequest) {
  try {
    const secret = await init()
    const a = req.nextUrl.searchParams.get('a')
    const b = await req.json().catch(() => ({}))
    let me: Me | null = null
    try {
      me = jwt.verify((req.headers.get('authorization') || '').slice(7), secret) as Me
    } catch {}

    if (a === 'register' || a === 'login') {
      const u = String(b.u || '').trim()
      const p = String(b.p || '')
      if (a === 'register') {
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(u)) return out({ e: 'Kullanıcı adı 3-20 karakter olmalı (harf, rakam, _)' }, 400)
        if (p.length < 6) return out({ e: 'Şifre en az 6 karakter olmalı' }, 400)
        if (p.length > 72) return out({ e: 'Şifre en fazla 72 karakter olabilir' }, 400)
        const [ex] = await sql`select id from users where lower(username)=lower(${u})`
        if (ex) return out({ e: 'Bu kullanıcı adı alınmış' }, 400)
        const [n] = await sql`insert into users(username, hash) values(${u}, ${await bcrypt.hash(p, 10)}) returning id, username`
        return out({ t: jwt.sign({ id: n.id, u: n.username }, secret, { expiresIn: '30d' }), u: n.username, av: 0 })
      }
      const [x] = await sql`select id, username, hash, av from users where lower(username)=lower(${u})`
      if (!x || !(await bcrypt.compare(p, x.hash))) return out({ e: 'Kullanıcı adı veya şifre yanlış' }, 400)
      return out({ t: jwt.sign({ id: x.id, u: x.username }, secret, { expiresIn: '30d' }), u: x.username, av: x.av })
    }

    if (!me) return out({ e: 'Giriş yapmalısın' }, 401)

    if (a === 'feed') {
      const u = b.u ? String(b.u) : null
      return out(await sql`select p.id, p.body, p.created, p.font, p.fs, p.img is not null as hasimg, u.username, u.av,
        (select count(*) from reacts where pid=p.id and v=1)::int as likes,
        (select count(*) from reacts where pid=p.id and v=-1)::int as dislikes,
        (select count(*) from comments where pid=p.id)::int as cc,
        (select v from reacts where pid=p.id and uid=${me.id}) as mine
        from posts p join users u on u.id=p.uid
        where (${u}::text is null or u.username=${u}) order by p.id desc limit 30`)
    }

    if (a === 'post') {
      const body = String(b.body || '').trim().slice(0, 280)
      const img = b.img ? String(b.img) : null
      if (img && (!/^data:image\/(jpeg|png|webp);base64,/.test(img) || img.length > 4000000))
        return out({ e: 'Fotoğraf geçersiz veya çok büyük' }, 400)
      if (!body && !img) return out({ e: 'Boş paylaşım olmaz' }, 400)
      const font = FONTS.includes(b.font) ? String(b.font) : 'sans'
      const fs = Math.min(FS_MAX, Math.max(FS_MIN, Math.round(Number(b.fs) || 16)))
      await sql`insert into posts(uid, body, img, font, fs) values(${me.id}, ${body}, ${img}, ${font}, ${fs})`
      return out({ ok: 1 })
    }

    if (a === 'del') {
      await sql`delete from posts where id=${Number(b.id) || 0} and uid=${me.id}`
      return out({ ok: 1 })
    }

    if (a === 'react') {
      const id = Number(b.id) || 0
      const v = Number(b.v) === -1 ? -1 : 1
      const [ex] = await sql`select v from reacts where pid=${id} and uid=${me.id}`
      if (ex && ex.v === v) await sql`delete from reacts where pid=${id} and uid=${me.id}`
      else await sql`insert into reacts(pid, uid, v) values(${id}, ${me.id}, ${v}) on conflict (pid, uid) do update set v=${v}`
      const [r] = await sql`select (select count(*) from reacts where pid=${id} and v=1)::int as likes,
        (select count(*) from reacts where pid=${id} and v=-1)::int as dislikes,
        (select v from reacts where pid=${id} and uid=${me.id}) as mine`
      return out(r)
    }

    if (a === 'comments') {
      return out(
        await sql`select c.id, c.body, c.created, u.username, u.av from comments c join users u on u.id=c.uid where c.pid=${Number(b.id) || 0} order by c.id limit 100`,
      )
    }

    if (a === 'comment') {
      const body = String(b.body || '').trim().slice(0, 200)
      if (!body) return out({ e: 'Boş yorum olmaz' }, 400)
      await sql`insert into comments(pid, uid, body) values(${Number(b.id) || 0}, ${me.id}, ${body})`
      return out({ ok: 1 })
    }

    if (a === 'user') {
      const [r] = await sql`select username, bio, av, created, (select count(*) from posts where uid=users.id)::int as posts from users where username=${String(b.u)}`
      return r ? out(r) : out({ e: 'Kullanıcı bulunamadı' }, 404)
    }

    if (a === 'bio') {
      await sql`update users set bio=${String(b.bio || '').slice(0, 160)} where id=${me.id}`
      return out({ ok: 1 })
    }

    if (a === 'avatar') {
      const av = Number(b.av)
      if (!Number.isInteger(av) || av < 0 || av > AVATAR_COUNT) return out({ e: 'Geçersiz profil simgesi' }, 400)
      await sql`update users set av=${av} where id=${me.id}`
      return out({ av })
    }

    return out({ e: 'Bilinmeyen işlem' }, 400)
  } catch (e) {
    console.error(e)
    return out({ e: 'Sunucu hatası, tekrar dene' }, 500)
  }
}
