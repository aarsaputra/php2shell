# Dockerfile lab php2shell (R2-05)
#
# Kenapa build lokal, bukan `image:` langsung:
#   Audit round 2 menemukan worker Apache berjalan sebagai www-data (uid 33)
#   sementara pemilik direktori /out di host adalah user operator (uid 1000).
#   Satu-satunya cara "menulis bukti" lalu adalah chown/chmod dari DALAM
#   container ke path host — tepat pola akses filesystem host yang dilarang.
#
# Jawabannya UID/GID MAPPING: user `p2s` di image dibuat dengan uid/gid yang
# SAMA dengan pemilik repo di host. Worker Apache lalu menulis /out sebagai
# uid host tanpa chown apa pun, dan tidak butuh DAC_OVERRIDE/FOWNER untuk itu.
#
# Argumen build diisi oleh lab_docker.sh / compose dari `id -u` / `id -g`.
FROM php:8.4.26-apache

ARG P2S_UID=1000
ARG P2S_GID=1000

RUN groupadd -g "${P2S_GID}" p2s 2>/dev/null || true \
 && useradd -u "${P2S_UID}" -g "${P2S_GID}" -M -s /usr/sbin/nologin p2s 2>/dev/null || true

# apache2-foreground membaca APACHE_RUN_USER/GROUP dari envvars (`:=` default),
# jadi variabel environment ini yang mengalihkan worker ke user mapping.
ENV APACHE_RUN_USER=p2s \
    APACHE_RUN_GROUP=p2s
