#!/bin/bash
# deploy.sh -- run on vaf to pull latest from ca9 and go live
# This script is called by the gitolite3 post-receive hook on ca9
# via: ssh -p 52266 aura@vaf "cd ~/websites/1id.com && bash deploy.sh"
#
# "Remote always wins, no arguments" policy:
#   git fetch --prune       -- get latest from ca9, clean stale refs
#   git reset --hard @{u}   -- force local to match upstream, discard local changes
#   git clean -ffdx          -- remove all untracked/ignored files (exact mirror of repo)
#   touch DANGER_...        -- re-create warning marker on production server

git fetch --prune
git reset --hard @{u}
git clean -ffdx
/usr/local/bin/git-meta2.py --restore
chmod o+x .                          # let nginx traverse into this repo directory
chmod -R o+rX public_html 2>/dev/null # let nginx read web files (git resets perms to 0600)
touch DANGER_IMPORTANT_This-folder-is-overwritten-upon-every-git-push-DO_NOT_CHANGE_ANY_FILES_IN_HERE

# Restart the API service on each deploy so code changes take effect
sudo systemctl restart oneid-api 2>/dev/null || true

# Rebuild and redeploy Keycloak SPI JAR only if source hash changed
SPI_SOURCE="keycloak-spi/src"
SPI_HASH_FILE="/opt/keycloak/providers/.oneid-spi-source-hash"
DEPLOYED_JAR="/opt/keycloak/providers/oneid-keycloak-spi.jar"
if [ -d "$SPI_SOURCE" ]; then
  CURRENT_HASH=$(find "$SPI_SOURCE" -type f | sort | xargs cat 2>/dev/null | md5sum | cut -d' ' -f1)
  PREVIOUS_HASH=$(cat "$SPI_HASH_FILE" 2>/dev/null || echo "none")
  if [ "$CURRENT_HASH" != "$PREVIOUS_HASH" ]; then
    echo "SPI source changed (hash: $PREVIOUS_HASH -> $CURRENT_HASH) -- rebuilding..."
    cd keycloak-spi && sudo bash build.sh 2>&1 && \
      sudo cp oneid-keycloak-spi.jar "$DEPLOYED_JAR" && \
      sudo chown keycloak:keycloak "$DEPLOYED_JAR" && \
      sudo chmod 644 "$DEPLOYED_JAR" && \
      sudo /opt/keycloak/bin/kc.sh build 2>&1 | tail -3 && \
      sudo systemctl restart keycloak 2>/dev/null && \
      echo "$CURRENT_HASH" | sudo tee "$SPI_HASH_FILE" > /dev/null && \
      echo "Keycloak SPI redeployed." || \
      echo "WARNING: Keycloak SPI rebuild/deploy failed"
    cd ..
  fi
fi
