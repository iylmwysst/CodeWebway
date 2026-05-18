(function () {
  class CodeWebwayTerminalRuntime {
    constructor(ctx) {
      this.ctx = ctx;
    }

    get stateMap() {
      return this.ctx.terminalHistoryState;
    }

    get term() {
      return this.ctx.getTerm();
    }

    closeSocket() {
      const ws = this.ctx.getWs();
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
      this.ctx.setWs(null);
    }

    resetTerminalHistoryView(terminalId) {
      this.stateMap.set(terminalId, {
        beforeSeq: null,
        nextSeq: null,
        loading: false,
        syncing: false,
        hasMore: true,
        chunks: [],
        tailText: '',
        bannerText: '',
        resumeMarkerText: '',
        trimmed: false,
        syncGapDetected: false,
        tailBeforeSeq: null,
        lastYdisp: 0,
      });
      this.ctx.terminalHistoryEl.classList.remove('open');
      this.ctx.terminalHistoryContentEl.textContent = '';
      this.ctx.terminalHistoryStatusEl.textContent = 'Scrollback history';
    }

    resetTerminalHistoryWindowForReplay(terminalId) {
      const state = this.stateMap.get(terminalId);
      if (!state) return;
      state.beforeSeq = null;
      state.chunks = [];
      state.tailText = '';
      state.resumeMarkerText = '';
      state.nextSeq = null;
      state.syncing = false;
      state.syncGapDetected = false;
      state.tailBeforeSeq = null;
      state.hasMore = true;
      state.trimmed = false;
      state.lastYdisp = 0;
    }

    countTerminalRows(text, cols = this.term?.cols || 80) {
      if (!text) return 0;
      let rows = 1;
      let col = 0;
      let escape = '';
      const width = Math.max(1, Number(cols) || 80);
      for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (escape) {
          escape += ch;
          if (
            (escape.startsWith('\x1b[') && /[\x40-\x7e]$/.test(escape)) ||
            (escape.startsWith('\x1b]') && (ch === '\x07' || escape.endsWith('\x1b\\'))) ||
            (!escape.startsWith('\x1b[') && !escape.startsWith('\x1b]') && escape.length >= 2)
          ) {
            escape = '';
          }
          continue;
        }
        if (ch === '\x1b') {
          escape = ch;
          continue;
        }
        if (ch === '\r') {
          col = 0;
          continue;
        }
        if (ch === '\n') {
          rows++;
          col = 0;
          continue;
        }
        if (ch === '\b') {
          col = Math.max(0, col - 1);
          continue;
        }
        if (ch === '\t') {
          col += 8 - (col % 8);
        } else if (ch >= ' ') {
          col++;
        }
        while (col >= width) {
          rows++;
          col -= width;
        }
      }
      return rows;
    }

    stripLeadingAnsiReplayFragment(text) {
      if (!text) return '';
      return text.replace(/^(?:\[?\??[\d;]{1,96}[A-Za-z@`~]|\][^\x07]*(?:\x07|\x1b\\))/, '');
    }

    trimTerminalTextToRows(text, maxRows, side = 'tail') {
      if (!text || !Number.isFinite(maxRows) || maxRows <= 0) return '';
      const width = Math.max(1, Number(this.term?.cols) || 80);
      const markers = [0];
      let row = 0;
      let col = 0;
      let escape = '';
      for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (escape) {
          escape += ch;
          if (
            (escape.startsWith('\x1b[') && /[\x40-\x7e]$/.test(escape)) ||
            (escape.startsWith('\x1b]') && (ch === '\x07' || escape.endsWith('\x1b\\'))) ||
            (!escape.startsWith('\x1b[') && !escape.startsWith('\x1b]') && escape.length >= 2)
          ) {
            escape = '';
          }
          continue;
        }
        if (ch === '\x1b') {
          escape = ch;
          continue;
        }
        if (ch === '\r') {
          col = 0;
          continue;
        }
        if (ch === '\n') {
          row++;
          col = 0;
          markers[row] = i + 1;
          continue;
        }
        if (ch === '\b') {
          col = Math.max(0, col - 1);
          continue;
        }
        if (ch === '\t') {
          col += 8 - (col % 8);
        } else if (ch >= ' ') {
          col++;
        }
        while (col >= width) {
          row++;
          col -= width;
          markers[row] = i + 1;
        }
      }
      const totalRows = row + 1;
      if (totalRows <= maxRows) return this.stripLeadingAnsiReplayFragment(text);
      if (side === 'head') {
        return this.stripLeadingAnsiReplayFragment(text.slice(0, markers[maxRows] ?? text.length));
      }
      const startRow = Math.max(0, totalRows - maxRows);
      return this.stripLeadingAnsiReplayFragment(text.slice(markers[startRow] ?? 0));
    }

    makeTrimmedHistoryChunk(chunk, side = 'tail') {
      if (!chunk || typeof chunk.data_b64 !== 'string') return chunk;
      const decoded = this.ctx.textDecoder.decode(this.ctx.b64ToBytes(chunk.data_b64));
      const text = this.trimTerminalTextToRows(decoded, this.ctx.TERMINAL_HISTORY_PAGE_ROWS, side);
      const bytes = this.ctx.textEncoder.encode(text);
      return { ...chunk, data_b64: this.ctx.bytesToB64(bytes), byte_len: bytes.length };
    }

    historyChunksRows(chunks) {
      return (chunks || []).reduce((total, chunk) => {
        if (!chunk || typeof chunk.data_b64 !== 'string') return total;
        return total + this.countTerminalRows(
          this.ctx.textDecoder.decode(this.ctx.b64ToBytes(chunk.data_b64))
        );
      }, 0);
    }

    trimOlderTerminalHistoryWindow(state) {
      if (!state || !Array.isArray(state.chunks)) return;
      let olderRows = this.historyChunksRows(state.chunks);
      while (state.chunks.length > 0 && olderRows > this.ctx.TERMINAL_HISTORY_MAX_OLDER_ROWS) {
        const removed = state.chunks.shift();
        olderRows -= this.historyChunksRows([removed]);
      }
      const tailRows = this.countTerminalRows(state.tailText || '');
      while (state.chunks.length > 0 && olderRows + tailRows > this.ctx.TERMINAL_HISTORY_MAX_LOADED_ROWS) {
        const removed = state.chunks.shift();
        olderRows -= this.historyChunksRows([removed]);
      }
      state.beforeSeq = state.chunks.length > 0 ? state.chunks[0].seq : state.tailBeforeSeq;
    }

    applyTerminalHistoryMetadata(terminalId, body) {
      const state = this.stateMap.get(terminalId);
      if (!state || !body) return;
      const chunks = Array.isArray(body.chunks) ? body.chunks : [];
      if (chunks.length > 0 && (state.beforeSeq === null || state.beforeSeq === undefined)) {
        state.beforeSeq = chunks[0].seq;
      } else if (chunks.length === 0 && (state.beforeSeq === null || state.beforeSeq === undefined)) {
        state.beforeSeq = Number(body.next_seq || 0);
      }
      state.tailBeforeSeq = state.beforeSeq;
      state.nextSeq = Number(body.next_seq || 0);
      state.hasMore = Boolean(body.has_more);
      state.trimmed = Boolean(body.trimmed);
    }

    setTerminalSyncState(terminalId, syncing, options = {}) {
      const state = this.stateMap.get(terminalId);
      if (!state) return;
      state.syncing = syncing;
      if (typeof options.gapDetected === 'boolean') {
        state.syncGapDetected = options.gapDetected;
      }
      if (this.ctx.getActiveTerminalId() !== terminalId) return;
      if (syncing) {
        this.ctx.terminalHistoryStatusEl.textContent = 'Catching up missed output…';
      } else if (state.syncGapDetected) {
        this.ctx.terminalHistoryStatusEl.textContent =
          'Recovered recent output; some older missed output had already been trimmed';
      }
    }

    decodeHistoryChunks(chunks) {
      return (chunks || [])
        .map((chunk) => this.ctx.textDecoder.decode(this.ctx.b64ToBytes(chunk.data_b64)))
        .join('');
    }

    terminalHistorySkippedMarker() {
      return '\r\nPrevious output skipped; scroll up to load older history\r\n';
    }

    maybeLoadOlderTerminalHistoryFromTop() {
      const activeTerminalId = this.ctx.getActiveTerminalId();
      if (!activeTerminalId || !this.term) return;
      const state = this.stateMap.get(activeTerminalId);
      if (!state || state.loading || !state.hasMore) return;
      const viewportY = Number(this.term.buffer?.active?.viewportY ?? state.lastYdisp ?? 0);
      if (viewportY <= 2) {
        this.loadOlderTerminalHistory(activeTerminalId);
      }
    }

    async replayRecentTerminalTail(terminalId, connectionId, options = {}) {
      const qs = new URLSearchParams({ limit: String(this.ctx.TERMINAL_REPLAY_HISTORY_CHUNKS) });
      const res = await this.ctx.api(
        `/api/terminals/${encodeURIComponent(terminalId)}/history?${qs.toString()}`
      );
      if (
        (connectionId !== null && connectionId !== undefined && connectionId !== this.ctx.getWsConnectionId()) ||
        !res.ok
      ) {
        return '';
      }
      const body = await res.json();
      this.applyTerminalHistoryMetadata(terminalId, body);
      const text = this.trimTerminalTextToRows(
        this.decodeHistoryChunks(body.chunks),
        this.ctx.TERMINAL_HISTORY_PAGE_ROWS,
        'tail'
      );
      const state = this.stateMap.get(terminalId);
      if (state) {
        state.tailText = text || '';
        state.resumeMarkerText = body.has_more ? this.terminalHistorySkippedMarker() : '';
        this.trimOlderTerminalHistoryWindow(state);
      }
      const replayText = `${state?.resumeMarkerText || ''}${text || ''}`;
      if (replayText && options.write !== false) {
        this.term.write(replayText);
      }
      return replayText;
    }

    async syncMissedTerminalOutput(terminalId, connectionId, options = {}) {
      const state = this.stateMap.get(terminalId);
      if (!state || state.nextSeq === null || state.nextSeq === undefined) return '';
      const previousNextSeq = Number(state.nextSeq || 0);
      let gapDetected = false;
      this.setTerminalSyncState(terminalId, true);
      try {
        const qs = new URLSearchParams({ limit: String(this.ctx.TERMINAL_REPLAY_HISTORY_CHUNKS) });
        const res = await this.ctx.api(
          `/api/terminals/${encodeURIComponent(terminalId)}/history?${qs.toString()}`
        );
        if (
          (connectionId !== null &&
            connectionId !== undefined &&
            connectionId !== this.ctx.getWsConnectionId()) ||
          !res.ok
        ) {
          return '';
        }
        const body = await res.json();
        const chunks = Array.isArray(body.chunks) ? body.chunks : [];
        const firstChunkSeq = chunks.length > 0 ? Number(chunks[0].seq) : Number(body.next_seq || 0);
        gapDetected = firstChunkSeq > previousNextSeq;
        this.applyTerminalHistoryMetadata(terminalId, body);
        const text = this.trimTerminalTextToRows(
          this.decodeHistoryChunks(chunks),
          this.ctx.TERMINAL_HISTORY_PAGE_ROWS,
          'tail'
        );
        state.chunks = [];
        state.tailText = text || '';
        state.resumeMarkerText =
          gapDetected || Boolean(body.has_more) ? this.terminalHistorySkippedMarker() : '';
        if (chunks.length > 0) {
          state.beforeSeq = firstChunkSeq;
          state.tailBeforeSeq = firstChunkSeq;
        }
        this.trimOlderTerminalHistoryWindow(state);
        if (options.write !== false) {
          this.rebuildTerminalBuffer(terminalId);
        }
        return `${state.resumeMarkerText || ''}${state.tailText || ''}`;
      } finally {
        this.setTerminalSyncState(terminalId, false, { gapDetected });
      }
    }

    rebuildTerminalBuffer(terminalId) {
      const state = this.stateMap.get(terminalId);
      if (!state) return;
      this.trimOlderTerminalHistoryWindow(state);
      const olderText = this.stripLeadingAnsiReplayFragment(this.decodeHistoryChunks(state.chunks));
      const liveText = this.ctx.readTerminalCache(terminalId);
      const markerText = state.hasMore || state.syncGapDetected ? state.resumeMarkerText || '' : '';
      this.term.write(this.ctx.TERMINAL_RESET_SEQUENCE);
      this.term.write(`${state.bannerText || ''}${olderText}${markerText}${state.tailText || ''}${liveText || ''}`);
      this.ctx.terminalHistoryStatusEl.textContent = state.hasMore
        ? 'Older scrollback loaded on demand'
        : state.trimmed
          ? 'Oldest retained scrollback loaded; earlier output was trimmed'
          : 'Start of retained scrollback';
    }

    async loadOlderTerminalHistory(terminalId) {
      let state = this.stateMap.get(terminalId);
      if (!state) {
        state = {
          beforeSeq: null,
          nextSeq: null,
          loading: false,
          syncing: false,
          hasMore: true,
          chunks: [],
          tailText: '',
          bannerText: '',
          resumeMarkerText: '',
          trimmed: false,
          syncGapDetected: false,
          tailBeforeSeq: null,
          lastYdisp: 0,
        };
        this.stateMap.set(terminalId, state);
      }
      if (state.loading || !state.hasMore) return;
      state.loading = true;
      this.ctx.terminalHistoryStatusEl.textContent = 'Loading older scrollback...';
      try {
        const qs = new URLSearchParams({ limit: String(this.ctx.TERMINAL_HISTORY_PAGE_LIMIT) });
        if (state.beforeSeq !== null && state.beforeSeq !== undefined) {
          qs.set('before_seq', String(state.beforeSeq));
        }
        const res = await this.ctx.api(
          `/api/terminals/${encodeURIComponent(terminalId)}/history?${qs.toString()}`
        );
        if (!res.ok) return;
        const body = await res.json();
        if (!body.chunks || body.chunks.length === 0) {
          state.hasMore = false;
          state.trimmed = Boolean(body.trimmed);
          this.rebuildTerminalBuffer(terminalId);
          return;
        }
        const normalizedChunks = body.chunks.map((chunk) => this.makeTrimmedHistoryChunk(chunk, 'tail'));
        state.beforeSeq = body.chunks[0].seq;
        state.hasMore = Boolean(body.has_more);
        state.trimmed = Boolean(body.trimmed);
        state.chunks = [...normalizedChunks, ...state.chunks];
        this.trimOlderTerminalHistoryWindow(state);
        this.rebuildTerminalBuffer(terminalId);
      } catch {
        this.ctx.terminalHistoryStatusEl.textContent = 'Cannot load older scrollback';
      } finally {
        state.loading = false;
      }
    }

    async connectTerminal(terminalId, options = {}) {
      const sessionAccess = this.ctx.getSessionAccess();
      if (sessionAccess.boundTerminalId && terminalId !== sessionAccess.boundTerminalId) {
        alert('This session is bound to another terminal tab.');
        return;
      }
      const switchingTerminal = terminalId !== this.ctx.getActiveTerminalId();
      this.ctx.setActiveTerminalId(terminalId);
      this.ctx.renderTerminalTabs();
      this.ctx.renderAgentSurface();
      if (!this.stateMap.has(terminalId)) {
        this.resetTerminalHistoryView(terminalId);
      }
      if (this.term && switchingTerminal) {
        this.term.write(this.ctx.TERMINAL_RESET_SEQUENCE);
      }

      const shouldSkipScrollback = true;
      const shouldReplayRecentTail = options.replayRecentTail !== false && !options.preserveBuffer;
      const agentSession = this.ctx.getAgentSession(terminalId);
      const preserveReplayPrefix = Boolean(
        agentSession && !options.freshAgentLaunch && shouldReplayRecentTail
      );
      const existingHistoryState = this.stateMap.get(terminalId);
      const hasHistoryBaseline = Boolean(
        existingHistoryState &&
          existingHistoryState.nextSeq !== null &&
          existingHistoryState.nextSeq !== undefined
      );
      if (this.term && shouldReplayRecentTail) {
        this.term.write(this.ctx.TERMINAL_RESET_SEQUENCE);
        if (!hasHistoryBaseline) {
          this.resetTerminalHistoryWindowForReplay(terminalId);
        }
        if (preserveReplayPrefix) {
          agentSession.replayPrefix = this.ctx.readTerminalCache(terminalId);
        } else if (!hasHistoryBaseline) {
          this.ctx.writeTerminalCache(terminalId, '');
          if (agentSession) {
            agentSession.replayPrefix = '';
          }
        }
        if (hasHistoryBaseline) {
          this.rebuildTerminalBuffer(terminalId);
        }
      }
      this.closeSocket();

      const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?terminal_id=${encodeURIComponent(terminalId)}&skip_scrollback=${shouldSkipScrollback ? 'true' : 'false'}`;
      const connectionId = this.ctx.nextWsConnectionId();
      const ws = new WebSocket(wsUrl);
      const localWs = ws;
      this.ctx.setWs(ws);
      ws.binaryType = 'arraybuffer';
      let replayReady = !shouldReplayRecentTail;
      const queuedLiveBytes = [];
      let terminalEnded = false;
      let pendingAckBytes = 0;

      const ackWrittenBytes = (byteLength) => {
        pendingAckBytes += byteLength;
        if (
          pendingAckBytes >= this.ctx.TERMINAL_WS_ACK_BYTES &&
          ws.readyState === WebSocket.OPEN
        ) {
          ws.send(JSON.stringify({ type: 'terminal_ack', bytes: pendingAckBytes }));
          pendingAckBytes = 0;
        }
      };

      const writeTerminalBytes = (bytes) => {
        this.term.write(bytes, () => ackWrittenBytes(bytes.byteLength || bytes.length || 0));
      };

      const writeLiveBytes = (bytes) => {
        const chunkText = this.ctx.textDecoder.decode(bytes);
        if (this.ctx.isAgentTerminal(terminalId)) {
          const transcriptText = this.ctx.consumeReplayPrefix(terminalId, chunkText);
          if (transcriptText) {
            this.ctx.appendTerminalCache(terminalId, transcriptText);
            this.ctx.captureAgentOutput(terminalId, transcriptText);
          }
        } else {
          this.ctx.appendTerminalCache(terminalId, chunkText);
        }
        writeTerminalBytes(bytes);
      };

      ws.onopen = async () => {
        if (connectionId !== this.ctx.getWsConnectionId()) return;
        this.ctx.restartingTerminals.delete(terminalId);
        this.ctx.updateTerminalSummaryState(terminalId, {
          status: 'running',
          exit_code: null,
          exit_success: null,
        });
        this.ctx.renderTerminalTabs();
        this.ctx.setRetries(0);
        this.ctx.setStatus(this.ctx.formatTerminalStatusLine(this.ctx.getTerminalSummaryById(terminalId)), '#4caf50');
        if (shouldReplayRecentTail) {
          const shouldShowStartupBanner = Boolean(
            options.startupBanner || this.ctx.pendingStartupBanners.has(terminalId)
          );
          let replayText = '';
          try {
            if (hasHistoryBaseline) {
              replayText = await this.syncMissedTerminalOutput(terminalId, connectionId, {
                write: !shouldShowStartupBanner,
              });
            } else {
              replayText = await this.replayRecentTerminalTail(terminalId, connectionId, {
                write: !shouldShowStartupBanner,
              });
            }
          } catch {
            // keep live output flowing
          }
          replayReady = true;
          if (shouldShowStartupBanner) {
            this.ctx.pendingStartupBanners.delete(terminalId);
            const state = this.stateMap.get(terminalId);
            if (state) {
              state.bannerText = this.ctx.STARTUP_BANNER;
            }
            this.term.write(this.ctx.TERMINAL_RESET_SEQUENCE);
            this.term.write(this.ctx.STARTUP_BANNER);
            if (replayText) {
              this.term.write(replayText);
            }
          }
          while (queuedLiveBytes.length > 0) {
            writeLiveBytes(queuedLiveBytes.shift());
          }
        }
        if (options.initialInput) {
          ws.send(this.ctx.textEncoder.encode(options.initialInput));
        }
        this.ctx.scheduleTerminalRecovery([0, 120]);
      };

      ws.onmessage = (e) => {
        if (connectionId !== this.ctx.getWsConnectionId()) return;
        if (typeof e.data === 'string') {
          const msg = JSON.parse(e.data);
          if (msg.type === 'session_expired') {
            this.ctx.showLogin('Session expired. Please login again.');
          } else if (msg.type === 'terminal_exited') {
            terminalEnded = true;
            this.ctx.updateTerminalSummaryState(terminalId, {
              status: 'exited',
              exit_code: Number.isInteger(msg.exit_code) ? msg.exit_code : null,
              exit_success: typeof msg.success === 'boolean' ? msg.success : null,
            });
            this.ctx.renderTerminalTabs();
            this.ctx.setStatus(this.ctx.formatTerminalStatusLine(this.ctx.getTerminalSummaryById(terminalId)), '#ffb74d');
          } else if (msg.type === 'terminal_closed') {
            terminalEnded = true;
            this.ctx.updateTerminalSummaryState(terminalId, {
              status: 'closed',
              exit_code: null,
              exit_success: null,
            });
            this.ctx.renderTerminalTabs();
            this.ctx.setStatus(this.ctx.formatTerminalStatusLine(this.ctx.getTerminalSummaryById(terminalId)), '#b0bec5');
          }
        } else {
          const bytes = new Uint8Array(e.data);
          if (!replayReady) {
            queuedLiveBytes.push(bytes);
            return;
          }
          writeLiveBytes(bytes);
        }
      };

      ws.onclose = async () => {
        if (connectionId !== this.ctx.getWsConnectionId()) return;
        if (this.ctx.getWs() !== localWs) return;
        if (terminalId !== this.ctx.getActiveTerminalId()) return;
        if (terminalEnded || this.ctx.restartingTerminals.has(terminalId)) {
          this.ctx.syncTerminalLifecycleBanner();
          return;
        }
        const loggingState = this.ctx.getLoggingState();
        if (loggingState.loggingOut) {
          this.ctx.clearLoggingState();
          await this.ctx.showLogin(loggingState.logoutNotice || 'Signed out.');
          return;
        }

        const activeSession = await this.ctx.hasActiveSession();
        if (activeSession === false) {
          await this.ctx.showLogin('Session expired. Please login again.');
          return;
        }

        const retries = this.ctx.bumpRetries();
        const delay = Math.min(5000, 600 * retries);
        this.ctx.setStatus(`Reconnecting (${retries})...`, '#ff9800');
        setTimeout(
          () =>
            this.connectTerminal(terminalId, {
              replayRecentTail: false,
              preserveBuffer: true,
            }),
          delay
        );
      };

      ws.onerror = () => {
        if (connectionId !== this.ctx.getWsConnectionId()) return;
        ws.close();
      };
    }
  }

  window.CodeWebwayTerminalRuntime = CodeWebwayTerminalRuntime;
})();
