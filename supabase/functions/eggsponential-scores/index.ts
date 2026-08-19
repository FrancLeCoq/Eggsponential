// ══════════════════════════════════════════════════════════════
//  eggsponential-scores — Edge Function Supabase
//  Classement du Mode Dore d'Eggsponential.
//  Meme construction que `chickenblast-scores`.
//
//  POST { initData, action:'top'|'submit', score?, best_tile?, moves? }
//    • 'top'    → podium + la ligne du joueur (avec son rang)
//    • 'submit' → enregistre un run puis renvoie le classement a jour
//
//  Un joueur = une ligne. On ne garde que son MEILLEUR score : un
//  nouveau run n'ecrase le precedent que s'il rapporte plus de points,
//  ou autant avec une tuile plus haute (logique cote SQL, fonction
//  eggsponential_submit_score).
//
//  L'identite n'est JAMAIS lue dans le corps de la requete : elle est
//  derivee des initData Telegram verifiees par HMAC-SHA256 avec
//  BOT_TOKEN (methode officielle). Le player_id est l'id Telegram,
//  comme dans chickenblast-scores.
//
//  La LECTURE reste ouverte (podium visible hors Telegram, sans la
//  ligne "moi"). Seule l'ECRITURE exige une signature valide.
// ══════════════════════════════════════════════════════════════

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const MAX_SCORE   = 10_000_000
const MAX_TILE    = 131_072      // 2^17
const MAX_MOVES   = 200_000
const MAX_AGE_SEC = 24 * 3600    // fenetre anti-rejeu sur auth_date
const TOP_N       = 10

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

/* ── HMAC helpers (Web Crypto) ─────────────────────────────── */
async function hmac(key: Uint8Array, msg: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg)))
}
function toHex(u8: Uint8Array): string {
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')
}
/** comparaison a temps constant, pour ne pas fuir d'information par le timing */
function sameHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/**
 * Verifie la signature d'un initData Telegram (methode bot token).
 * data_check_string = champs tries alphabetiquement, "cle=valeur" joints par \n.
 * On teste la variante avec et sans le champ "signature" (ajoute plus tard par
 * Telegram pour la validation Ed25519 tierce) : les deux exigent BOT_TOKEN,
 * donc accepter l'une ou l'autre n'ouvre aucune porte a un faussaire.
 */
async function verifyInitData(initData: string, token: string): Promise<boolean> {
  const params = new URLSearchParams(initData)
  const hash = params.get('hash')
  if (!hash) return false
  params.delete('hash')

  const secret = await hmac(new TextEncoder().encode('WebAppData'), token)
  const entries = Array.from(params.entries())
  const want = hash.toLowerCase()

  for (const withSig of [true, false]) {
    const pairs = withSig ? entries : entries.filter(([k]) => k !== 'signature')
    const dcs = pairs
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n')
    if (sameHex(toHex(await hmac(secret, dcs)), want)) return true
  }
  return false
}

function authDateFresh(initData: string): boolean {
  const raw = new URLSearchParams(initData).get('auth_date')
  if (!raw) return false
  const age = Date.now() / 1000 - Number(raw)
  return Number.isFinite(age) && age >= -300 && age <= MAX_AGE_SEC
}

/** retire les caracteres de controle et borne la longueur des pseudos */
function clean(s: string): string {
  return String(s ?? '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 32)
}

/** Identite derivee des initData VERIFIEES uniquement. */
function parseUser(initData: string): { id: string; name: string; username: string | null } | null {
  try {
    const userStr = new URLSearchParams(initData).get('user')
    if (!userStr) return null
    const u = JSON.parse(userStr)
    if (u?.id === undefined || u?.id === null) return null
    return {
      id:       String(u.id),
      name:     clean([u.first_name, u.last_name].filter(Boolean).join(' ')) || 'Player',
      username: u.username ? clean(String(u.username)) : null,
    }
  } catch { return null }
}

/** entier strict dans [0, max] — pas de coercition de chaine */
function intIn(v: unknown, max: number): number | null {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > max) return null
  return v
}
/** tuile 2048 : puissance de 2 entre 2 et 2^17 */
function tileIn(v: unknown): number | null {
  const n = intIn(v, MAX_TILE)
  if (n === null || n < 2 || (n & (n - 1)) !== 0) return null
  return n
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS })
  const headers = { 'Content-Type': 'application/json', ...CORS }

  try {
    const body = await req.json().catch(() => ({}))
    const action = body?.action === 'submit' ? 'submit' : 'top'
    const initData: string = typeof body?.initData === 'string' ? body.initData : ''

    const token = Deno.env.get('BOT_TOKEN') || ''
    let user: { id: string; name: string; username: string | null } | null = null
    let authFailed = false

    if (initData) {
      const signed = token ? await verifyInitData(initData, token) : false
      if (!token) {
        console.warn('eggsponential-scores: BOT_TOKEN missing, refusing writes')
        authFailed = true
      } else if (!signed) {
        console.warn('eggsponential-scores: initData signature rejected')
        authFailed = true
      } else if (!authDateFresh(initData)) {
        console.warn('eggsponential-scores: initData too old')
        authFailed = true
      } else {
        user = parseUser(initData)
        if (!user) authFailed = true
      }
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    )

    // ── ECRITURE : signature obligatoire ──────────────────────
    let submitted: { improved: boolean; previous: number | null } | null = null

    if (action === 'submit') {
      if (!user) {
        return new Response(JSON.stringify({
          ok: false,
          error: authFailed ? 'Invalid session' : 'Missing initData',
          authFailed,
        }), { status: 401, headers })
      }
      const score = intIn(body?.score, MAX_SCORE)
      const tile  = tileIn(body?.best_tile)
      const moves = intIn(body?.moves, MAX_MOVES)
      if (score === null || tile === null || moves === null) {
        return new Response(JSON.stringify({ ok: false, error: 'Invalid score' }), { status: 400, headers })
      }
      const { data, error } = await supabase.rpc('eggsponential_submit_score', {
        p_player_id: user.id,      // jamais lu dans la requete
        p_name:      user.name,    // idem
        p_username:  user.username,
        p_score:     score,
        p_best_tile: tile,
        p_moves:     moves,
      })
      if (error) {
        console.error('submit rpc error:', error.message)
        return new Response(JSON.stringify({ ok: false, error: 'Could not save score' }), { status: 500, headers })
      }
      submitted = data as typeof submitted
    }

    // ── LECTURE : ouverte, "moi" seulement si signature valide ─
    // Elle suit aussi une ecriture : le client repart avec le classement
    // a jour sans avoir a rappeler la fonction.
    const { data: board, error: boardErr } = await supabase.rpc('eggsponential_leaderboard', {
      p_player_id: user?.id ?? null,
      p_limit:     TOP_N,
    })
    if (boardErr) {
      console.error('leaderboard rpc error:', boardErr.message)
      return new Response(JSON.stringify({ ok: false, error: 'Could not read leaderboard' }), { status: 500, headers })
    }

    return new Response(JSON.stringify({
      ok: true,
      authFailed,
      top:   (board as any)?.top   ?? [],
      me:    (board as any)?.me    ?? null,
      total: (board as any)?.total ?? 0,
      improved: submitted?.improved ?? null,
      previous: submitted?.previous ?? null,
    }), { headers })

  } catch (err) {
    console.error('eggsponential-scores fatal:', String(err))
    return new Response(JSON.stringify({ ok: false, error: 'Server error' }), { status: 500, headers })
  }
})
