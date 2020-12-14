#!/bin/sh
#Public Domain
cargo test --no-run --message-format=json | jq -r "select(.profile.test == true) | .filenames[]" | while read -r bin; do
    sudo -- "$bin" --test-threads=1
done