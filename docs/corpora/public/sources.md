# Sources (fetched 2026-10-14, HTTP status checked with curl)
1. dcg, destructive_command_guard: https://github.com/Dicklesworthstone/destructive_command_guard (200). Agent pre-exec guard with git, fs, db, k8s, docker, cloud packs. Dozens of patterns, ~25 used here. Code license: check the repo LICENSE. Borrow the patterns as ideas.
2. claude-code-safety-net: https://github.com/kenryu42/claude-code-safety-net (200). Claude Code hook that catches git discards, rm -rf, and nested `bash -c` / interpreter forms. About 10 used.
3. Tecmint "10 most dangerous commands": https://www.tecmint.com/10-most-dangerous-commands-you-should-never-execute-on-linux/ (200). Classic list: rm -rf /, fork bomb, mkfs, dd, > /dev/sda, mv to /dev/null, wget|sh, chmod 777. About 10. Quote for testing only (fair use).
4. ShellCheck SC2115 and SC2114: https://www.shellcheck.net/wiki/SC2115 and https://www.shellcheck.net/wiki/SC2114 (200). Empty-variable rm and the space-split /usr pattern. 3 used. GPL tool; wiki is reference.
5. Steam for Linux #3671: https://github.com/ValveSoftware/steam-for-linux/issues/3671 (200). `rm -rf "$STEAMROOT/"*` with an empty variable. 1 command plus 1 variant.
6. Bumblebee #123: https://github.com/MrMEEE/bumblebee-Old-and-abbandoned/issues/123 (200). Commit a047be8 also returns 200. `rm -rf /usr /lib/nvidia-current/xorg/xorg`.
7. GitLab 2017 postmortem: https://about.gitlab.com/blog/2017/02/10/postmortem-of-database-outage-of-january-31/ (200). rm -rf on a Postgres data dir on the wrong host.
8. pg-safeupdate: https://github.com/eradman/pg-safeupdate (200). Blocks DELETE/UPDATE with no WHERE. 2 used.
9. safe-rm (launchpad): https://launchpad.net/safe-rm (200). Protected-path list (/etc, /usr/lib, /home...). shell-safe-rm: https://github.com/kaelzhang/shell-safe-rm (200). rm-protection: https://github.com/alanzchen/rm-protection (200). trash-cli: https://github.com/andreafrancia/trash-cli (200). These are mostly ideas, not command lists.
10. Fork bomb, Wikipedia: https://en.wikipedia.org/wiki/Fork_bomb (200). Bash and Perl variants. CC BY-SA.
11. AWS S3 2017 postmortem: https://aws.amazon.com/message/41926/ (200). A mistyped internal playbook command removed too many servers. The exact command is not published, so no line was added.
12. R-Judge, arXiv 2401.10019: https://arxiv.org/abs/2401.10019 (200). Agent-safety risk benchmark. Not mined; count unknown.
13. HN item 8896268: https://news.ycombinator.com/item?id=8896268 (200). Not mined. Topic not confirmed.
Blocked or unverified (403): Reddit r/sysadmin "worst command" thread https://www.reddit.com/r/sysadmin/comments/2g2wn2/whats_the_worst_command_you_ran/ ; Server Fault https://serverfault.com/questions/337082/how-do-i-prevent-accidental-rm-rf ; MySQL safe-updates docs https://dev.mysql.com/doc/refman/8.0/en/mysql-tips.html
Caveat: link status was verified, but not every command was matched word for word against its page. Many lines are `derived:` variants built from the source's pattern.

## AI-agent incidents (X) — added 2026-10-14
All are claims from posts/postmortems unless noted; nothing executed. Full rows in x-commands.tsv.
- Replit agent deletes SaaStr prod DB during code freeze (Jul 2025): https://x.com/jasonlk/status/1946069562723897802
- Claude Code `rm -rf tests/ patches/ plan/ ~/` wipes Mac home (Dec 2025): https://x.com/andersonbcdefg/status/1998246944939069816 , https://simonwillison.net/2025/Dec/9/claude/
- Claude Code rm -rf from root, GH #10077 (Oct 2025): https://github.com/anthropics/claude-code/issues/10077
- Claude Code `terraform destroy` on DataTalks.Club prod (Feb 2026): https://x.com/theagenticdaily/status/2081727088126779769 , https://aishippingblog.com/p/how-i-dropped-our-production-database
- Antigravity `rmdir /s /q d:\` wipes drive (Dec 2025): https://x.com/tengyanAI/status/1997865526597492920
- the builder agent rmdir quoting wipes D: (Sep 2026): https://forum.cursor.com/t/windows-agent-rmdir-broken-quoting-wiped-d-ticket-t-f90960-grok-4-6-extra-high/172345
- the builder / Gemini agents `npx prisma db push --force-reset` on prod: https://x.com/suresh_a0/status/1949028341736263732 , https://x.com/HolyGau9/status/2012346542477156685
- Claude Code `git reset --hard HEAD` after /branch: https://x.com/benhylak/status/2034399719632580785 ; steipete reports Claude ran reset --hard on Codex refactor: https://x.com/steipete/status/1987764540918894843
- Codex deletes Windows profile on folder move (Mar 2026): https://x.com/InTheNous/status/2031148100480532646
- Gemini CLI move/mkdir file loss (Jul 2025): https://x.com/TrendingNews2x7/status/1949771122787967055
- the builder agent + Opus 4.6 deletes PocketOS prod DB + backups (Apr 2026): https://x.com/EB_XdotO/status/2051249414195585343
- Claude Code sub-agent 8.3-alias rm -rf, ~116GB (GH #99193, Oct 2026): https://x.com/ClaudeCodeRev/status/2107762329282613447

## Drunk/tired/typo incidents — added 2026-10-14
Claims from posts/threads unless official; nothing executed. Rows in drunk-commands.tsv.
- Drunk missing-semicolon `DATE=... mv $DATE/* .` -> `mv /* .` on prod: https://www.reddit.com/r/linux/comments/15fq1i/member_of_rdrunk_recalls_how_he_once_screwed_up/ (Reddit via search snippet)
- Drunk on-call deletes 500GB oradata: https://www.reddit.com/r/sysadmin/comments/kjby6/whats_the_drunkest_youve_been_when_your_support/
- AWS S3 2017 mistyped input (official): https://aws.amazon.com/message/41926/
- Spotify deleted prod k8s cluster twice (wrong terminal): https://x.com/Horgix/status/1131098939095175169
- Wrong-window DROP TABLE overwrote subpoenaed data: https://x.com/loadnabox/status/1381723113814028288
- dd to wrong disk: https://snee.la/ramblings/dd-the-data-destroyer/ , https://askubuntu.com/questions/1376552/
- Wrong-window reboot / 11 PM rm -rf /var/www: https://x.com/burhan/status/1159082258021703683 , https://x.com/tecmint/status/2041719214134702482

## Stack Exchange sources — added 2026-10-14
Rows in se-commands.tsv (43; commands copied from question bodies' <code> blocks; nothing executed; Windows skipped).
Method: public SE API, no key. `GET https://api.stackexchange.com/2.3/search/advanced?q=<q>&site=<site>&filter=withbody&pagesize=15|10`
- Sites: unix, serverfault, superuser, askubuntu.
- Batch 1 (sort=votes): "accidentally rm -rf", "accidentally chmod -R", "accidentally chown -R", "accidentally mv", "dd wrong disk", "accidentally deleted home" (24 requests).
- Batch 2 (sort=relevance): "accidentally find -delete", "chmod .* parent directory", "variable empty rm -rf", "accidentally overwrote file redirect", "space rm -rf accidentally" (20 requests; mostly empty).
- Total 44 requests; quota_remaining went 299 → ~274 (quota is counted per site). No Data Explorer, Wayback, or dump used.
- Dedupe: exact-string match against commands.tsv/.txt, x-commands.tsv, drunk-commands.tsv (0 dropped; near-variants such as `rm -r /*` vs `rm -rf /*` kept).

## Stack Exchange pass 2 — added 2026-10-14
Rows in se2-commands.tsv (24; nothing executed; Linux only). Data Explorer not used (needs browser/login); SE API only.
- 53 requests: q= searches for find -delete / empty variable / .* parent / script deleted / overwrote (5 sites incl. stackoverflow), plus title= searches ("accidentally ran", "find -delete", "accidentally overwrote", "chown -R .*", "deleted everything", "drunk", "rm -rf $", etc.). Quota per site stayed >200.
- Commands taken from <code> blocks plus a prose regex (ran/typed/executed ...).
- Dedupe: normalized whitespace, sudo prefix, -r/-R/-fr/-r -f → -rf, quotes, $VAR names; checked against all existing tsv/txt (1 dropped: rm -rf $cache_dir/*).
