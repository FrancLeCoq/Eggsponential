-- ══════════════════════════════════════════════════════════════
--  Eggsponential — classement mondial du Mode Doré
--
--  Meme construction que le classement de Chicken Reflex :
--    * une seule ligne par joueur = son MEILLEUR score ;
--    * ecriture uniquement quand le joueur bat son record
--      (upsert conditionnel) -> une partie ordinaire n'ecrit rien ;
--    * lecture en UN seul appel (TOP N + la ligne du joueur) ;
--    * les deux RPC sont SECURITY DEFINER et reservees au
--      service_role : seule l'Edge Function `eggsponential-scores`
--      peut les appeler, et elle derive l'identite des initData
--      Telegram verifiees par HMAC. Le client ne choisit jamais
--      son player_id.
--
--  Le classement ne concerne que le Mode Dore (reserve aux
--  detenteurs de $FRANC). `mode` existe quand meme pour pouvoir
--  ouvrir un second classement plus tard sans migration de donnees.
-- ══════════════════════════════════════════════════════════════

create table if not exists public.eggs_scores (
  id          uuid primary key default gen_random_uuid(),
  player_id   text not null,
  player_name text not null default 'Poulet',
  score       int  not null,
  best_tile   int  not null default 2,   -- plus haute tuile atteinte (2..131072)
  moves       int  not null default 0,
  mode        text not null default 'golden',
  day         date not null default ((now() at time zone 'Europe/Paris')::date),
  created_at  timestamptz not null default now(),
  constraint eggs_scores_player_mode_key unique (player_id, mode)
);

comment on table public.eggs_scores is
  'Eggsponential : une ligne par joueur et par mode = son MEILLEUR score. Ecrite uniquement quand le joueur bat son record (upsert conditionnel dans submit_eggs_score). day/created_at = date du record. Lecture via eggs_board().';

create index if not exists eggs_scores_board_idx
  on public.eggs_scores (mode, score desc, best_tile desc);

alter table public.eggs_scores enable row level security;

-- Aucune policy : anon/authenticated ne touchent jamais la table en direct.
revoke all on public.eggs_scores from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Upsert conditionnel : n'ecrit que si la partie bat le record du joueur.
-- Renvoie improved=false quand rien n'a change.
-- ---------------------------------------------------------------------------
create or replace function public.submit_eggs_score(
  p_player_id   text,
  p_player_name text,
  p_score       int,
  p_best_tile   int,
  p_moves       int,
  p_mode        text default 'golden'
) returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_day      date := (now() at time zone 'Europe/Paris')::date;
  v_pid      text := nullif(btrim(p_player_id), '');
  v_name     text := left(coalesce(nullif(btrim(p_player_name), ''), 'Poulet'), 24);
  v_old_s    int;
  v_old_t    int;
  v_last     timestamptz;
  v_improved boolean;
  v_best     int;
  v_best_t   int;
  v_rank     int;
  v_total    int;
begin
  -- Garde-fous : le client est public, on ne lui fait pas confiance.
  if v_pid is null or length(v_pid) > 64 then
    raise exception 'invalid player_id';
  end if;
  if p_mode is null or p_mode not in ('golden', 'classic') then
    raise exception 'invalid mode';
  end if;
  -- Une tuile est forcement une puissance de 2, entre l'oeuf et 2^17.
  if p_best_tile is null or p_best_tile < 2 or p_best_tile > 131072
     or (p_best_tile & (p_best_tile - 1)) <> 0 then
    raise exception 'invalid best_tile';
  end if;
  if p_moves is null or p_moves < 0 or p_moves > 200000 then
    raise exception 'invalid moves';
  end if;
  -- Le score d'une grille 4x4 est borne par sa plus haute tuile : atteindre T
  -- rapporte T*(log2 T - 1), et le reste du plateau ne peut pas en rajouter
  -- plus que quelques fois autant (x2 en Mode Dore). x8 laisse une marge
  -- confortable tout en rejetant les scores inventes.
  if p_score is null or p_score < 0
     or p_score > 8 * p_best_tile * (log(2, p_best_tile::numeric))::int then
    raise exception 'inconsistent score';
  end if;

  -- Anti-spam : on n'ecrit que sur record, deux records a 3 s d'intervalle
  -- ne sont pas une partie de 2048.
  select created_at into v_last
    from public.eggs_scores where player_id = v_pid and mode = p_mode;
  if v_last is not null and now() - v_last < interval '3 seconds' then
    raise exception 'too fast';
  end if;

  select score, best_tile into v_old_s, v_old_t
    from public.eggs_scores where player_id = v_pid and mode = p_mode;

  -- Meilleur = score superieur, ou score egal avec une tuile plus haute
  -- (c'est exactement la regle de departage du classement).
  v_improved := v_old_s is null
             or p_score > v_old_s
             or (p_score = v_old_s and p_best_tile > v_old_t);

  if v_improved then
    insert into public.eggs_scores
      (player_id, player_name, score, best_tile, moves, mode, day, created_at)
    values
      (v_pid, v_name, p_score, p_best_tile, p_moves, p_mode, v_day, now())
    on conflict (player_id, mode) do update
      set player_name = excluded.player_name,
          score       = excluded.score,
          best_tile   = excluded.best_tile,
          moves       = excluded.moves,
          day         = excluded.day,
          created_at  = excluded.created_at
      where excluded.score > public.eggs_scores.score
         or (excluded.score = public.eggs_scores.score
             and excluded.best_tile > public.eggs_scores.best_tile);
  else
    -- Pas de record, mais on garde le pseudo a jour sans toucher au score.
    update public.eggs_scores
       set player_name = v_name
     where player_id = v_pid and mode = p_mode and player_name is distinct from v_name;
  end if;

  with ranked as (
    select player_id, score, best_tile,
           rank() over (order by score desc, best_tile desc)::int as rank
      from public.eggs_scores where mode = p_mode
  )
  select r.score, r.best_tile, r.rank, (select count(*) from ranked)
    into v_best, v_best_t, v_rank, v_total
    from ranked r where r.player_id = v_pid;

  return json_build_object(
    'ok',        true,
    'improved',  v_improved,
    'name',      v_name,
    'score',     p_score,
    'best',      v_best,
    'best_tile', v_best_t,
    'rank',      v_rank,
    'players',   v_total
  );
end;
$$;

-- ---------------------------------------------------------------------------
-- Classement : TOP N + la ligne du joueur (meme hors du top).
-- Un seul appel pour toute la page classement.
-- ---------------------------------------------------------------------------
create or replace function public.eggs_board(
  p_mode      text default 'golden',
  p_limit     int  default 10,
  p_player_id text default null
) returns json
language sql
stable
security definer
set search_path = public
as $$
  with ranked as (
    select s.player_id, s.player_name, s.score, s.best_tile,
           rank() over (order by s.score desc, s.best_tile desc)::int as rank
      from public.eggs_scores s
     where s.mode = coalesce(p_mode, 'golden')
  ), topn as (
    select * from ranked
     order by rank, best_tile desc
     limit least(greatest(coalesce(p_limit, 10), 1), 50)
  )
  select json_build_object(
    'mode',    coalesce(p_mode, 'golden'),
    'players', (select count(*) from ranked),
    'top',     coalesce((select json_agg(json_build_object(
                           'rank',      t.rank,
                           'name',      t.player_name,
                           'score',     t.score,
                           'best_tile', t.best_tile,
                           'is_me',     (p_player_id is not null and t.player_id = p_player_id))
                           order by t.rank, t.best_tile desc)
                         from topn t), '[]'::json),
    'me',      (select json_build_object('rank', r.rank, 'name', r.player_name,
                                         'score', r.score, 'best_tile', r.best_tile)
                  from ranked r
                 where p_player_id is not null and r.player_id = p_player_id)
  );
$$;

-- Les deux RPC ne sont appelables que par l'Edge Function `eggsponential-scores`
-- (service_role). Rien d'exploitable avec la seule cle publishable.
revoke all on function public.submit_eggs_score(text, text, int, int, int, text)
  from public, anon, authenticated;
revoke all on function public.eggs_board(text, int, text)
  from public, anon, authenticated;
grant execute on function public.submit_eggs_score(text, text, int, int, int, text) to service_role;
grant execute on function public.eggs_board(text, int, text) to service_role;
