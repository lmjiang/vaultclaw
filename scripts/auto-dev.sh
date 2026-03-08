#!/bin/bash
# auto-dev.sh — Autonomous Claude Code Max development loop
# Reads AUTOPILOT.md for goals, auto-restarts on exit, reports to OpenClaw
# Background monitor detects prompts, completions, and stuck states

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

export LLVM_COV=/opt/homebrew/opt/llvm/bin/llvm-cov
export LLVM_PROFDATA=/opt/homebrew/opt/llvm/bin/llvm-profdata

RESTART_COUNT=0
MAX_RAPID_RESTARTS=3
MIN_RUN_SECONDS=60
SESSION_NAME="vaultclaw-dev"
MONITOR_PID=""
POLL_INTERVAL=10
IDLE_NOTIFY_THRESHOLD=180    # 3 min idle at shell prompt → notify task done
STUCK_THRESHOLD=600          # 10 min no output change → stuck
LAST_NOTIFY_FILE="/tmp/vaultclaw-monitor-last-notify"

notify_openclaw() {
  local msg="$1"
  echo "[MONITOR $(date '+%H:%M:%S')] NOTIFY: $msg"
  openclaw system event --text "$msg" --mode now --timeout 10000 2>/dev/null || true
}

# Rate-limit notifications: at most once per 3 minutes
should_notify() {
  local now=$(date +%s)
  local last=0
  if [ -f "$LAST_NOTIFY_FILE" ]; then
    last=$(cat "$LAST_NOTIFY_FILE" 2>/dev/null || echo "0")
  fi
  local diff=$((now - last))
  if [ "$diff" -ge 180 ]; then
    echo "$now" > "$LAST_NOTIFY_FILE"
    return 0
  fi
  return 1
}

# Capture last N lines from tmux pane
capture_pane() {
  tmux capture-pane -t "$SESSION_NAME" -p -S -20 2>/dev/null || echo ""
}

monitor_and_approve() {
  local last_output_hash=""
  local last_change=$(date +%s)
  local shell_idle_since=0

  while true; do
    sleep "$POLL_INTERVAL"

    local pane
    pane=$(capture_pane)
    [ -z "$pane" ] && continue

    local current_hash
    current_hash=$(echo "$pane" | md5 -q 2>/dev/null || echo "$pane" | md5sum 2>/dev/null | cut -d' ' -f1)

    # Track output changes
    if [ "$current_hash" != "$last_output_hash" ]; then
      last_output_hash="$current_hash"
      last_change=$(date +%s)
      shell_idle_since=0
    fi

    local last5
    last5=$(echo "$pane" | tail -5)

    # --- Pattern 1: Plan mode numbered selection ---
    # "1. Yes, clear context and bypass permissions"
    if echo "$last5" | grep -qE "^\s*(❯\s*)?(1\.|2\.|3\.|4\.)\s*(Yes|No).*"; then
      if echo "$last5" | grep -q "Would you like to proceed\|clear context"; then
        echo "[MONITOR $(date '+%H:%M:%S')] Plan approval prompt — selecting option 1 (clear + bypass)"
        tmux send-keys -t "$SESSION_NAME" "1" && sleep 0.3 && tmux send-keys -t "$SESSION_NAME" Enter
        sleep 3
        last_change=$(date +%s)
        continue
      fi
    fi

    # --- Pattern 2: Generic "Would you like to proceed" ---
    if echo "$last5" | grep -q "Would you like to proceed"; then
      echo "[MONITOR $(date '+%H:%M:%S')] Plan mode detected — auto-approving"
      tmux send-keys -t "$SESSION_NAME" Enter
      sleep 2
      last_change=$(date +%s)
      continue
    fi

    # --- Pattern 3: Permission prompts ---
    if echo "$last5" | grep -qE "Allow\?|Deny|allow this|approve this"; then
      echo "[MONITOR $(date '+%H:%M:%S')] Permission prompt — sending 'y'"
      tmux send-keys -t "$SESSION_NAME" 'y' Enter
      sleep 2
      last_change=$(date +%s)
      continue
    fi

    # --- Pattern 4: Continue/Enter prompts ---
    if echo "$last5" | grep -qE "Press Enter to|Continue\?|Do you want to continue"; then
      echo "[MONITOR $(date '+%H:%M:%S')] Interactive prompt — sending Enter"
      tmux send-keys -t "$SESSION_NAME" Enter
      sleep 2
      last_change=$(date +%s)
      continue
    fi

    # --- Pattern 5: Task completed (idle shell prompt) ---
    # Claude Code shows ❯ when ready for input; if idle for IDLE_NOTIFY_THRESHOLD, task is done
    if echo "$last5" | grep -qE "^❯\s*$|^────.*\n❯"; then
      if [ "$shell_idle_since" -eq 0 ]; then
        shell_idle_since=$(date +%s)
      else
        local idle_dur=$(( $(date +%s) - shell_idle_since ))
        if [ "$idle_dur" -ge "$IDLE_NOTIFY_THRESHOLD" ]; then
          if should_notify; then
            # Grab context about what Max just finished
            local context
            context=$(tmux capture-pane -t "$SESSION_NAME" -p -S -40 2>/dev/null | head -20 || echo "unknown")
            notify_openclaw "🏁 Max completed a task in vaultclaw-dev (idle ${idle_dur}s at shell prompt). Last output: $(echo "$context" | tr '\n' ' ' | head -c 300)"
          fi
          shell_idle_since=$(date +%s)  # Reset to avoid spam
        fi
      fi
      continue
    else
      shell_idle_since=0
    fi

    # --- Pattern 6: Stuck detection (no output change for STUCK_THRESHOLD) ---
    local now=$(date +%s)
    local no_change=$(( now - last_change ))
    if [ "$no_change" -ge "$STUCK_THRESHOLD" ]; then
      if should_notify; then
        notify_openclaw "⚠️ Max may be stuck in vaultclaw-dev (no output change for ${no_change}s). Last 3 lines: $(echo "$pane" | tail -3 | tr '\n' ' ' | head -c 200)"
      fi
      last_change=$now  # Reset
    fi

    # --- Pattern 7: Error/crash indicators ---
    if echo "$last5" | grep -qiE "BLOCKED|panic|fatal|segfault|SIGKILL|out of memory"; then
      if should_notify; then
        notify_openclaw "🚨 Max hit an error in vaultclaw-dev: $(echo "$last5" | grep -iE 'BLOCKED|panic|fatal|segfault|SIGKILL|out of memory' | head -1 | head -c 200)"
      fi
    fi

    # --- Pattern 8: Max explicitly reports via system event text ---
    if echo "$last5" | grep -q "openclaw system event"; then
      # Max is trying to report something — let him handle it
      continue
    fi
  done
}

TASK='Read AUTOPILOT.md for your current mission and priorities. Read CLAUDE.md for project context. Execute the highest priority incomplete task. Follow the quality gates. When a task is done, commit, push, and immediately start the next task in the priority order. Keep working through issues until blocked or out of tasks.'

while true; do
  START_TIME=$(date +%s)
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Claude Code session (restart #$RESTART_COUNT)..."

  # Start background monitor
  monitor_and_approve &
  MONITOR_PID=$!
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Background monitor started (PID: $MONITOR_PID)"

  # Run Claude Code
  claude --dangerously-skip-permissions "$TASK" 2>&1 || true

  # Stop background monitor
  if [ -n "$MONITOR_PID" ]; then
    kill "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    MONITOR_PID=""
  fi

  END_TIME=$(date +%s)
  ELAPSED=$((END_TIME - START_TIME))

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Claude Code exited after ${ELAPSED}s"

  # Notify on exit
  notify_openclaw "🔄 Max exited vaultclaw-dev after ${ELAPSED}s (restart #$RESTART_COUNT). Auto-restarting..."

  # Detect rapid exits
  if [ "$ELAPSED" -lt "$MIN_RUN_SECONDS" ]; then
    RESTART_COUNT=$((RESTART_COUNT + 1))
    echo "[WARN] Rapid exit (${ELAPSED}s). Count: $RESTART_COUNT/$MAX_RAPID_RESTARTS"

    if [ "$RESTART_COUNT" -ge "$MAX_RAPID_RESTARTS" ]; then
      notify_openclaw "🚨 BLOCKED: Claude Code crashed $MAX_RAPID_RESTARTS times rapidly. Last run: ${ELAPSED}s. Manual intervention needed."
      exit 1
    fi
  else
    RESTART_COUNT=0
  fi

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Restarting in 10s..."
  sleep 10
done
