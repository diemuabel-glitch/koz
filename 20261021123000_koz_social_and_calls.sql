create table if not exists public.koz_posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  body text not null default '' check (char_length(body) <= 2000),
  media_path text,
  media_type text check (media_type in ('image', 'video')),
  created_at timestamptz not null default now(),
  constraint koz_posts_content_present check (
    char_length(trim(body)) > 0 or media_path is not null
  ),
  constraint koz_posts_media_pair check (
    (media_path is null and media_type is null)
    or (media_path is not null and media_type is not null)
  )
);

create table if not exists public.koz_likes (
  post_id uuid not null references public.koz_posts (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

create table if not exists public.koz_comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.koz_posts (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  body text not null check (char_length(trim(body)) between 1 and 1000),
  created_at timestamptz not null default now()
);

create table if not exists public.koz_follows (
  follower_id uuid not null references auth.users (id) on delete cascade,
  following_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),
  constraint koz_follows_distinct_users check (follower_id <> following_id)
);

create table if not exists public.koz_call_sessions (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.chat_conversations (id) on delete cascade,
  caller_id uuid not null references auth.users (id) on delete cascade,
  callee_id uuid not null references auth.users (id) on delete cascade,
  call_type text not null check (call_type in ('audio', 'video')),
  state text not null default 'ringing' check (state in ('ringing', 'accepted', 'declined', 'ended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint koz_call_sessions_distinct_users check (caller_id <> callee_id)
);

create table if not exists public.koz_call_signals (
  id uuid primary key default gen_random_uuid(),
  call_id uuid not null references public.koz_call_sessions (id) on delete cascade,
  sender_id uuid not null references auth.users (id) on delete cascade,
  receiver_id uuid not null references auth.users (id) on delete cascade,
  kind text not null check (kind in ('offer', 'answer', 'candidate')),
  payload jsonb not null check (pg_column_size(payload) <= 65536),
  created_at timestamptz not null default now(),
  constraint koz_call_signals_distinct_users check (sender_id <> receiver_id)
);

create index if not exists koz_posts_created_idx on public.koz_posts (created_at desc);
create index if not exists koz_posts_user_created_idx on public.koz_posts (user_id, created_at desc);
create index if not exists koz_comments_post_created_idx on public.koz_comments (post_id, created_at);
create index if not exists koz_follows_following_idx on public.koz_follows (following_id);
create index if not exists koz_call_sessions_callee_idx on public.koz_call_sessions (callee_id, created_at desc);
create index if not exists koz_call_signals_call_created_idx on public.koz_call_signals (call_id, created_at);
create index if not exists koz_call_signals_receiver_idx on public.koz_call_signals (receiver_id, created_at);

alter table public.user_profiles alter column discoverable set default true;
alter table public.koz_posts enable row level security;
alter table public.koz_likes enable row level security;
alter table public.koz_comments enable row level security;
alter table public.koz_follows enable row level security;
alter table public.koz_call_sessions enable row level security;
alter table public.koz_call_signals enable row level security;

revoke all on public.koz_posts, public.koz_likes, public.koz_comments,
  public.koz_follows, public.koz_call_sessions, public.koz_call_signals
  from anon, authenticated;
grant select, insert, delete on public.koz_posts to authenticated;
grant select, insert, delete on public.koz_likes to authenticated;
grant select, insert, delete on public.koz_comments to authenticated;
grant select, insert, delete on public.koz_follows to authenticated;
grant select on public.koz_call_sessions to authenticated;
grant select, insert on public.koz_call_signals to authenticated;

drop policy if exists "KOZ members read posts" on public.koz_posts;
create policy "KOZ members read posts" on public.koz_posts
  for select to authenticated using (true);

drop policy if exists "Members publish their own posts" on public.koz_posts;
create policy "Members publish their own posts" on public.koz_posts
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and (media_path is null or split_part(media_path, '/', 1) = (select auth.uid())::text)
  );

drop policy if exists "Members delete their own posts" on public.koz_posts;
create policy "Members delete their own posts" on public.koz_posts
  for delete to authenticated using (user_id = (select auth.uid()));

drop policy if exists "KOZ members read likes" on public.koz_likes;
create policy "KOZ members read likes" on public.koz_likes
  for select to authenticated using (true);

drop policy if exists "Members like posts" on public.koz_likes;
create policy "Members like posts" on public.koz_likes
  for insert to authenticated
  with check (user_id = (select auth.uid()) and exists (
    select 1 from public.koz_posts as posts where posts.id = post_id
  ));

drop policy if exists "Members remove their likes" on public.koz_likes;
create policy "Members remove their likes" on public.koz_likes
  for delete to authenticated using (user_id = (select auth.uid()));

drop policy if exists "KOZ members read comments" on public.koz_comments;
create policy "KOZ members read comments" on public.koz_comments
  for select to authenticated using (true);

drop policy if exists "Members comment as themselves" on public.koz_comments;
create policy "Members comment as themselves" on public.koz_comments
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.koz_posts as posts where posts.id = post_id)
  );

drop policy if exists "Members delete their comments" on public.koz_comments;
create policy "Members delete their comments" on public.koz_comments
  for delete to authenticated using (user_id = (select auth.uid()));

drop policy if exists "KOZ members read follows" on public.koz_follows;
create policy "KOZ members read follows" on public.koz_follows
  for select to authenticated using (true);

drop policy if exists "Members follow visible profiles" on public.koz_follows;
create policy "Members follow visible profiles" on public.koz_follows
  for insert to authenticated
  with check (
    follower_id = (select auth.uid())
    and following_id <> (select auth.uid())
    and exists (
      select 1 from public.user_profiles as profiles
      where profiles.user_id = following_id and profiles.discoverable
    )
  );

drop policy if exists "Members unfollow profiles" on public.koz_follows;
create policy "Members unfollow profiles" on public.koz_follows
  for delete to authenticated using (follower_id = (select auth.uid()));

drop policy if exists "Participants read their calls" on public.koz_call_sessions;
create policy "Participants read their calls" on public.koz_call_sessions
  for select to authenticated
  using ((select auth.uid()) in (caller_id, callee_id));

drop policy if exists "Participants read call signals" on public.koz_call_signals;
create policy "Participants read call signals" on public.koz_call_signals
  for select to authenticated
  using ((select auth.uid()) in (sender_id, receiver_id));

drop policy if exists "Call participants send signals" on public.koz_call_signals;
create policy "Call participants send signals" on public.koz_call_signals
  for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and exists (
      select 1 from public.koz_call_sessions as calls
      where calls.id = call_id
        and calls.state in ('ringing', 'accepted')
        and calls.caller_id in (sender_id, receiver_id)
        and calls.callee_id in (sender_id, receiver_id)
        and receiver_id = case
          when calls.caller_id = sender_id then calls.callee_id
          else calls.caller_id
        end
    )
  );

create or replace function public.start_koz_call(p_conversation_id uuid, p_call_type text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  conversation public.chat_conversations%rowtype;
  peer_id uuid;
  new_call_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Sign in is required.';
  end if;
  if p_call_type not in ('audio', 'video') then
    raise exception 'Unsupported call type.';
  end if;

  select * into conversation
  from public.chat_conversations
  where id = p_conversation_id
    and auth.uid() in (user_one, user_two);
  if not found then
    raise exception 'Conversation not found.';
  end if;
  if exists (
    select 1 from public.chat_blocks as blocks
    where (blocks.blocker_id = conversation.user_one and blocks.blocked_id = conversation.user_two)
       or (blocks.blocker_id = conversation.user_two and blocks.blocked_id = conversation.user_one)
  ) then
    raise exception 'Calls are unavailable for this conversation.';
  end if;
  if not exists (
    select 1 from public.chat_requests as requests
    where requests.id = conversation.request_id and requests.status = 'accepted'
  ) then
    raise exception 'The conversation is not accepted.';
  end if;

  peer_id := case when auth.uid() = conversation.user_one
    then conversation.user_two else conversation.user_one end;
  insert into public.koz_call_sessions (conversation_id, caller_id, callee_id, call_type)
  values (p_conversation_id, auth.uid(), peer_id, p_call_type)
  returning id into new_call_id;
  return new_call_id;
end;
$$;

create or replace function public.respond_koz_call(p_call_id uuid, p_accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in is required.';
  end if;
  update public.koz_call_sessions
  set state = case when p_accept then 'accepted' else 'declined' end,
      updated_at = now()
  where id = p_call_id
    and callee_id = auth.uid()
    and state = 'ringing';
  if not found then
    raise exception 'Call not found or no longer ringing.';
  end if;
end;
$$;

create or replace function public.finish_koz_call(p_call_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in is required.';
  end if;
  update public.koz_call_sessions
  set state = 'ended', updated_at = now()
  where id = p_call_id
    and auth.uid() in (caller_id, callee_id)
    and state in ('ringing', 'accepted');
  if not found then
    raise exception 'Call not found or already finished.';
  end if;
end;
$$;

revoke all on function public.start_koz_call(uuid, text) from public;
revoke all on function public.respond_koz_call(uuid, boolean) from public;
revoke all on function public.finish_koz_call(uuid) from public;
grant execute on function public.start_koz_call(uuid, text) to authenticated;
grant execute on function public.respond_koz_call(uuid, boolean) to authenticated;
grant execute on function public.finish_koz_call(uuid) to authenticated;

insert into storage.buckets (id, name, public, file_size_limit)
values ('koz-media', 'koz-media', true, 52428800)
on conflict (id) do update
set public = excluded.public, file_size_limit = excluded.file_size_limit;

drop policy if exists "KOZ media public read" on storage.objects;
create policy "KOZ media public read" on storage.objects
  for select to public using (bucket_id = 'koz-media');

drop policy if exists "Members upload their KOZ media" on storage.objects;
create policy "Members upload their KOZ media" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'koz-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

drop policy if exists "Members delete their KOZ media" on storage.objects;
create policy "Members delete their KOZ media" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'koz-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
  );

do $$
begin
  alter publication supabase_realtime add table public.koz_call_sessions;
exception
  when duplicate_object then null;
  when undefined_object then null;
end;
$$;

do $$
begin
  alter publication supabase_realtime add table public.koz_call_signals;
exception
  when duplicate_object then null;
  when undefined_object then null;
end;
$$;
