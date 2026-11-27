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
const PIC_MAX = 280000 // ~200 KB

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
    await sql`alter table posts add column if not exists font text not null default 'sans'`
    await sql`alter table posts add column if not exists fs int not null default 16`
    await sql`alter table posts add column if not exists pub boolean not null default false`
    await sql`alter table users add column if not exists pic text`
    await sql`alter table users add column if not exists pv int not null default 0`
    await sql`alter table users add column if not exists priv boolean not null default false`
    await sql`create table if not exists follows(follower int not null references users(id) on delete cascade, followee int not null references users(id) on delete cascade, st text not null default 'accepted', created timestamptz default now(), primary key(follower, followee))`
    await sql`create index if not exists follows_followee_idx on follows(followee)`
    await sql`create table if not exists notifs(id serial primary key, uid int not null references users(id) on delete cascade, actor int not null references users(id) on delete cascade, type text not null, pid int references posts(id) on delete cascade, seen boolean not null default false, created timestamptz default now())`
    await sql`create index if not exists notifs_uid_idx on notifs(uid, id desc)`
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

const verify = (tok: string, secret: string): Me | null => {
  try {
    return jwt.verify(tok, secret) as Me
  } catch {
    return null
  }
}

// Bu kişi bu paylaşımı görebilir mi? (kendi paylaşımı, herkese açık hesap, herkese açık paylaşım veya takipçi)
const canSee = async (pid: number, uid: number) => {
  const [r] = await sql`select 1 from posts p join users u on u.id=p.uid where p.id=${pid} and (p.uid=${uid} or not u.priv or p.pub or exists(select 1 from follows f where f.follower=${uid} and f.followee=p.uid and f.st='accepted'))`
  return !!r
}

const notify = async (uid: number, actor: number, type: string, pid: number | null) => {
  if (uid !== actor) await sql`insert into notifs(uid, actor, type, pid) values(${uid}, ${actor}, ${type}, ${pid})`
}

const serve = (data: unknown, cache: string) => {
  const m = data && String(data).match(/^data:(image\/\w+);base64,(.*)$/)
  if (!m) return new Response(null, { status: 404 })
  return new Response(Buffer.from(m[2], 'base64'), { headers: { 'Content-Type': m[1], 'Cache-Control': cache } })
}

export async function GET(req: NextRequest) {
  try {
    const secret = await init()
    const p = req.nextUrl.searchParams
    const a = p.get('a')
    if (a === 'pic') {
      const [r] = await sql`select pic from users where username=${p.get('u') || ''}`
      return serve(r?.pic, 'public, max-age=31536000, immutable')
    }
    if (a === 'img') {
      const me = verify(p.get('t') || '', secret)
      const id = Number(p.get('id')) || 0
      if (!me || !(await canSee(id, me.id))) return new Response(null, { status: 404 })
      const [r] = await sql`select img from posts where id=${id}`
      return serve(r?.img, 'private, max-age=31536000, immutable')
    }
    return out({ e: 'Bilinmeyen işlem' }, 400)
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
    const me = verify((req.headers.get('authorization') || '').slice(7), secret)

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
        return out({ t: jwt.sign({ id: n.id, u: n.username }, secret, { expiresIn: '30d' }), u: n.username, pv: 0, priv: false })
      }
      const [x] = await sql`select id, username, hash, pv, priv from users where lower(username)=lower(${u})`
      if (!x || !(await bcrypt.compare(p, x.hash))) return out({ e: 'Kullanıcı adı veya şifre yanlış' }, 400)
      return out({ t: jwt.sign({ id: x.id, u: x.username }, secret, { expiresIn: '30d' }), u: x.username, pv: x.pv, priv: x.priv })
    }

    if (!me) return out({ e: 'Giriş yapmalısın' }, 401)

    if (a === 'feed') {
      const u = b.u ? String(b.u) : null
      return out(await sql`select p.id, p.body, p.created, p.font, p.fs, p.pub, p.img is not null as hasimg, u.username, u.pv, u.priv,
        (select count(*) from reacts where pid=p.id and v=1)::int as likes,
        (select count(*) from reacts where pid=p.id and v=-1)::int as dislikes,
        (select count(*) from comments where pid=p.id)::int as cc,
        (select v from reacts where pid=p.id and uid=${me.id}) as mine
        from posts p join users u on u.id=p.uid
        where (${u}::text is null or u.username=${u})
          and (p.uid=${me.id} or not u.priv or p.pub or exists(select 1 from follows f where f.follower=${me.id} and f.followee=p.uid and f.st='accepted'))
        order by p.id desc limit 30`)
    }

    if (a === 'post') {
      const body = String(b.body || '').trim().slice(0, 280)
      const img = b.img ? String(b.img) : null
      if (img && (!/^data:image\/(jpeg|png|webp);base64,/.test(img) || img.length > 4000000))
        return out({ e: 'Fotoğraf geçersiz veya çok büyük' }, 400)
      if (!body && !img) return out({ e: 'Boş paylaşım olmaz' }, 400)
      const font = FONTS.includes(b.font) ? String(b.font) : 'sans'
      const fs = Math.min(FS_MAX, Math.max(FS_MIN, Math.round(Number(b.fs) || 16)))
      await sql`insert into posts(uid, body, img, font, fs, pub) values(${me.id}, ${body}, ${img}, ${font}, ${fs}, ${!!b.pub})`
      return out({ ok: 1 })
    }

    if (a === 'del') {
      await sql`delete from posts where id=${Number(b.id) || 0} and uid=${me.id}`
      return out({ ok: 1 })
    }

    if (a === 'react') {
      const id = Number(b.id) || 0
      const v = Number(b.v) === -1 ? -1 : 1
      if (!(await canSee(id, me.id))) return out({ e: 'Bu paylaşıma erişemezsin' }, 403)
      const [pp] = await sql`select uid from posts where id=${id}`
      const [ex] = await sql`select v from reacts where pid=${id} and uid=${me.id}`
      await sql`delete from notifs where actor=${me.id} and pid=${id} and type in ('like','dislike')`
      if (ex && ex.v === v) await sql`delete from reacts where pid=${id} and uid=${me.id}`
      else {
        await sql`insert into reacts(pid, uid, v) values(${id}, ${me.id}, ${v}) on conflict (pid, uid) do update set v=${v}`
        await notify(pp.uid, me.id, v === 1 ? 'like' : 'dislike', id)
      }
      const [r] = await sql`select (select count(*) from reacts where pid=${id} and v=1)::int as likes,
        (select count(*) from reacts where pid=${id} and v=-1)::int as dislikes,
        (select v from reacts where pid=${id} and uid=${me.id}) as mine`
      return out(r)
    }

    if (a === 'comments') {
      const id = Number(b.id) || 0
      if (!(await canSee(id, me.id))) return out({ e: 'Bu paylaşıma erişemezsin' }, 403)
      return out(await sql`select c.id, c.body, c.created, u.username, u.pv from comments c join users u on u.id=c.uid where c.pid=${id} order by c.id limit 100`)
    }

    if (a === 'comment') {
      const id = Number(b.id) || 0
      const body = String(b.body || '').trim().slice(0, 200)
      if (!body) return out({ e: 'Boş yorum olmaz' }, 400)
      if (!(await canSee(id, me.id))) return out({ e: 'Bu paylaşıma erişemezsin' }, 403)
      const [pp] = await sql`select uid from posts where id=${id}`
      await sql`insert into comments(pid, uid, body) values(${id}, ${me.id}, ${body})`
      await notify(pp.uid, me.id, 'comment', id)
      return out({ ok: 1 })
    }

    if (a === 'user') {
      const [r] = await sql`select u.id, u.username, u.bio, u.pv, u.priv,
        (select count(*) from posts where uid=u.id)::int as posts,
        (select count(*) from follows where followee=u.id and st='accepted')::int as followers,
        (select count(*) from follows where follower=u.id and st='accepted')::int as following,
        (select st from follows where follower=${me.id} and followee=u.id) as st
        from users u where u.username=${String(b.u)}`
      return r ? out({ ...r, id: undefined, own: r.id === me.id }) : out({ e: 'Kullanıcı bulunamadı' }, 404)
    }

    if (a === 'bio') {
      await sql`update users set bio=${String(b.bio || '').slice(0, 160)} where id=${me.id}`
      return out({ ok: 1 })
    }

    if (a === 'pic') {
      const pic = b.pic ? String(b.pic) : null
      if (pic && (!/^data:image\/(jpeg|png|webp);base64,/.test(pic) || pic.length > PIC_MAX)) return out({ e: 'Profil fotoğrafı geçersiz veya 200 KB üstünde' }, 400)
      const pv = pic ? Math.floor(Date.now() / 1000) : 0
      await sql`update users set pic=${pic}, pv=${pv} where id=${me.id}`
      return out({ pv })
    }

    if (a === 'priv') {
      const v = !!b.v
      await sql`update users set priv=${v} where id=${me.id}`
      if (!v) {
        await sql`update follows set st='accepted' where followee=${me.id} and st='pending'`
        await sql`update notifs set type='follow' where uid=${me.id} and type='follow_req'`
      }
      return out({ priv: v })
    }

    if (a === 'follow') {
      const [t] = await sql`select id, priv from users where username=${String(b.u)}`
      if (!t) return out({ e: 'Kullanıcı bulunamadı' }, 404)
      if (t.id === me.id) return out({ e: 'Kendini takip edemezsin' }, 400)
      const [ex] = await sql`select st from follows where follower=${me.id} and followee=${t.id}`
      await sql`delete from notifs where actor=${me.id} and uid=${t.id} and type in ('follow','follow_req')`
      if (ex) {
        await sql`delete from follows where follower=${me.id} and followee=${t.id}`
        return out({ st: null })
      }
      const st = t.priv ? 'pending' : 'accepted'
      await sql`insert into follows(follower, followee, st) values(${me.id}, ${t.id}, ${st})`
      await notify(t.id, me.id, t.priv ? 'follow_req' : 'follow', null)
      return out({ st })
    }

    if (a === 'followans') {
      const [t] = await sql`select id from users where username=${String(b.u)}`
      if (!t) return out({ e: 'Kullanıcı bulunamadı' }, 404)
      if (b.ok) {
        await sql`update follows set st='accepted' where follower=${t.id} and followee=${me.id} and st='pending'`
        await sql`update notifs set type='follow' where uid=${me.id} and actor=${t.id} and type='follow_req'`
      } else {
        await sql`delete from follows where follower=${t.id} and followee=${me.id} and st='pending'`
        await sql`delete from notifs where uid=${me.id} and actor=${t.id} and type='follow_req'`
      }
      return out({ ok: 1 })
    }

    if (a === 'follows') {
      const [t] = await sql`select id, priv from users where username=${String(b.u)}`
      if (!t) return out({ e: 'Kullanıcı bulunamadı' }, 404)
      if (t.priv && t.id !== me.id) {
        const [f] = await sql`select 1 from follows where follower=${me.id} and followee=${t.id} and st='accepted'`
        if (!f) return out({ e: 'Bu hesap gizli' }, 403)
      }
      return out(
        b.t === 'following'
          ? await sql`select u.username, u.pv from follows f join users u on u.id=f.followee where f.follower=${t.id} and f.st='accepted' order by f.created desc limit 100`
          : await sql`select u.username, u.pv from follows f join users u on u.id=f.follower where f.followee=${t.id} and f.st='accepted' order by f.created desc limit 100`,
      )
    }

    if (a === 'notifs') {
      const rows = await sql`select n.id, n.type, n.seen, n.created, u.username, u.pv, left(p.body, 60) as snip,
        exists(select 1 from follows f where f.follower=n.actor and f.followee=${me.id} and f.st='pending') as pending
        from notifs n join users u on u.id=n.actor left join posts p on p.id=n.pid
        where n.uid=${me.id} order by n.id desc limit 50`
      await sql`update notifs set seen=true where uid=${me.id} and not seen`
      return out(rows)
    }

    if (a === 'badge') {
      const [r] = await sql`select count(*)::int as n from notifs where uid=${me.id} and not seen`
      return out(r)
    }

    return out({ e: 'Bilinmeyen işlem' }, 400)
  } catch (e) {
    console.error(e)
    return out({ e: 'Sunucu hatası, tekrar dene' }, 500)
  }
}
