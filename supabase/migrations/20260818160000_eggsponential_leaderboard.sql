-- ══════════════════════════════════════════════════════════════
--  Eggsponential — classement mondial du Mode Doré
--
--  Construction reprise telle quelle du classement de Chicken Blast :
--    * un joueur = UNE ligne, on ne garde que son MEILLEUR score ;
--    * l'ecriture n'ecrase le precedent que s'il fait mieux (score,
--      puis plus haute tuile en departage) ;
--    * une lecture rend le podium + la ligne du joueur avec son rang,
--      meme hors podium, en un seul appel ;
--    * RLS active sans aucune policy, et les deux RPC ne sont
--      executables que par le service_role : seule l'Edge Function
--      `eggsponential-scores` peut les appeler, et elle derive
--      l'identite des initData Telegram verifiees par HMAC.
--
--  Le classement ne concerne que le Mode Dore, reserve aux detenteurs
--  de $FRANC.
-- ══════════════════════════════════════════════════════════════

create table if not exists public.eggsponential_scores (
  player_id   text primary key,
  player_name text        not null default 'Anon',
  username    text,
  score       int         not null default 0,
  best_tile   int         not null default 2,   -- plus haute tuile atteinte
  moves       int         not null default 0,
  games       int         not null default 0,
  best_at     timestamptz not null default now(),
  created_at  timestamptz not null default now()
);

comment on table public.eggsponential_scores is
  'Eggsponential : une ligne par joueur = son MEILLEUR score en Mode Dore. Ecrite uniquement quand le joueur bat son record (le client ne rappelle pas Supabase sinon). Ecriture via eggsponential_submit_score(), lecture via eggsponential_leaderboard().';

create index if not exists eggsponential_scores_board_idx
  on public.eggsponential_scores (score desc, best_tile desc, best_at asc);

alter table public.eggsponential_scores enable row level security;
-- Aucune policy : anon/authenticated ne touchent jamais la table en direct.

-- ---------------------------------------------------------------------------
-- Enregistre une partie. Le score n'est remplace que s'il fait mieux.
-- ---------------------------------------------------------------------------
create or replace function public.eggsponential_submit_score(
  p_player_id text,
  p_name      text,
  p_username  text,
  p_score     int,
  p_best_tile int,
  p_moves     int default 0
) returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_prev_score integer;
  v_prev_tile  integer;
  v_score      integer := greatest(coalesce(p_score, 0), 0);
  v_tile       integer := greatest(coalesce(p_best_tile, 2), 2);
  v_moves      integer := greatest(coalesce(p_moves, 0), 0);
  v_better     boolean;
begin
  if p_player_id is null or p_player_id = '' then
    raise exception 'player_id required';
  end if;
  -- Une tuile est forcement une puissance de 2 : le client est public.
  if v_tile > 131072 or (v_tile & (v_tile - 1)) <> 0 then
    raise exception 'invalid best_tile';
  end if;
  -- Le score d'une grille 4x4 est borne par sa plus haute tuile : atteindre T
  -- rapporte T*(log2 T - 1), et le reste du plateau ne peut pas en rajouter
  -- beaucoup plus (x2 en Mode Dore). x8 laisse une marge confortable tout en
  -- rejetant les scores inventes.
  if v_score > 8 * v_tile * (log(2, v_tile::numeric))::int then
    raise exception 'inconsistent score';
  end if;

  select score, best_tile into v_prev_score, v_prev_tile
    from eggsponential_scores
   where player_id = p_player_id;

  -- Meilleur = plus de points, ou autant de points avec une tuile plus haute.
  v_better := v_prev_score is null
              or v_score > v_prev_score
              or (v_score = v_prev_score and v_tile > v_prev_tile);

  insert into eggsponential_scores
    (player_id, player_name, username, score, best_tile, moves, games, best_at)
  values
    (p_player_id, coalesce(nullif(p_name, ''), 'Anon'), p_username, v_score, v_tile, v_moves, 1, now())
  on conflict (player_id) do update set
    player_name = coalesce(nullif(excluded.player_name, ''), eggsponential_scores.player_name),
    username    = coalesce(excluded.username, eggsponential_scores.username),
    games       = eggsponential_scores.games + 1,
    score       = case when v_better then excluded.score     else eggsponential_scores.score     end,
    best_tile   = case when v_better then excluded.best_tile else eggsponential_scores.best_tile end,
    moves       = case when v_better then excluded.moves     else eggsponential_scores.moves     end,
    best_at     = case when v_better then now()              else eggsponential_scores.best_at   end;

  return jsonb_build_object(
    'improved',      v_better and v_score > 0,
    'previous',      v_prev_score,
    'previous_tile', v_prev_tile
  );
end
$function$;

-- ---------------------------------------------------------------------------
-- Classement : TOP N + la ligne du joueur (meme hors du top), en un appel.
-- ---------------------------------------------------------------------------
create or replace function public.eggsponential_leaderboard(
  p_player_id text default null,
  p_limit     int  default 10
) returns jsonb
language sql
stable
security definer
set search_path to 'public'
as $function$
  with ranked as (
    select player_id, player_name, score, best_tile, best_at,
           row_number() over (
             order by score desc, best_tile desc, best_at asc, player_id asc
           ) as rk
      from eggsponential_scores
     where score > 0
  )
  select jsonb_build_object(
    'top', coalesce((
      select jsonb_agg(jsonb_build_object(
               'name',  player_name,
               'score', score,
               'tile',  best_tile,
               'rank',  rk,
               'me',    (p_player_id is not null and player_id = p_player_id)
             ) order by rk)
        from ranked
       where rk <= greatest(coalesce(p_limit, 10), 1)
    ), '[]'::jsonb),
    'me', (
      select jsonb_build_object(
               'name',  player_name,
               'score', score,
               'tile',  best_tile,
               'rank',  rk
             )
        from ranked
       where p_player_id is not null and player_id = p_player_id
    ),
    'total', (select count(*) from ranked)
  )
$function$;

-- Les deux RPC ne sont appelables que par l'Edge Function `eggsponential-scores`.
revoke all on function public.eggsponential_submit_score(text, text, text, int, int, int)
  from public, anon, authenticated;
revoke all on function public.eggsponential_leaderboard(text, int)
  from public, anon, authenticated;
grant execute on function public.eggsponential_submit_score(text, text, text, int, int, int) to service_role;
grant execute on function public.eggsponential_leaderboard(text, int) to service_role;
