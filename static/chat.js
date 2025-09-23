/* global ROOM, USERNAME */
(function () {
  const socket = io();

  const body = document.body;
  const ROOM_INIT = body.getAttribute('data-room');
  const USERNAME = body.getAttribute('data-username');

  // DOM refs
  const messagesEl = document.getElementById('messages');
  const messageForm = document.getElementById('message-form');
  const messageInput = document.getElementById('message-input');
  const typingEl = document.getElementById('typing-indicator');
  const ctxName = document.getElementById('ctx-name');
  const chatListEl = document.getElementById('chat-list');
  const codeTop = document.getElementById('room-code');
  const codeSide = document.getElementById('room-code-side');

  // Local state
  const messageIdToRow = new Map();
  let currentRoom = ROOM_INIT;
  const recentRooms = new Map(); // roomCode -> {id, ts}

  function digitsOnly(v){ return (v||'').replace(/\D+/g,'').slice(0,4); }
  function normalizeCode(v){ const d=digitsOnly(v); return d.padStart(4,'0'); }
  function touchRecent(room){ recentRooms.set(room, { id: room, ts: Date.now() }); renderRecent(); }
  function renderRecent(){ if (!chatListEl) return; const items = Array.from(recentRooms.values()).sort((a,b)=>b.ts-a.ts).slice(0,50); chatListEl.innerHTML=''; items.forEach(it=>{ const li=document.createElement('li'); li.className='list-group-item d-flex justify-content-between align-items-center chat-item'; li.setAttribute('data-code', it.id); const left=document.createElement('div'); left.className='d-flex align-items-center gap-2'; const av=document.createElement('div'); av.className='avatar'; av.textContent=it.id; const txt=document.createElement('div'); txt.innerHTML = `<div class="fw-semibold">Room ${it.id}</div><div class="small text-muted">recent</div>`; left.appendChild(av); left.appendChild(txt); li.appendChild(left); const btn=document.createElement('button'); btn.type='button'; btn.className='btn btn-sm btn-outline-secondary open-room'; btn.textContent='Open'; btn.setAttribute('data-code', it.id); li.appendChild(btn); chatListEl.appendChild(li); }); }

  if (chatListEl){ chatListEl.addEventListener('click', function(e){ const btn = e.target && (e.target.closest && e.target.closest('button.open-room')); let raw; if (btn){ raw = btn.getAttribute('data-code'); } else { const item = e.target && (e.target.closest && e.target.closest('.chat-item')); if (item) raw = item.getAttribute('data-code'); } if (!raw) return; e.preventDefault(); const code = normalizeCode(raw); if (codeTop) codeTop.value = code; if (codeSide) codeSide.value = code; updateContextToRoom(code); }); }
  function updateContextToRoom(code){ currentRoom = normalizeCode(code); ctxName.textContent = currentRoom; messagesEl.innerHTML=''; socket.emit('join_room', { room: currentRoom }); addSystemMessage(`Joined room ${currentRoom} at ${new Date().toLocaleString()}`); touchRecent(currentRoom); }

  function scrollToBottom() { messagesEl.scrollTop = messagesEl.scrollHeight; }
  function addSystemMessage(text) { const el = document.createElement('div'); el.className = 'text-muted small my-1'; el.textContent = text; messagesEl.appendChild(el); scrollToBottom(); }
  function initials(name){ const parts=(name||'').split(/\s+/).filter(Boolean); const a=parts[0]?parts[0][0]:''; const b=parts[1]?parts[1][0]:''; return (a+b||name.slice(0,2)).toUpperCase(); }

  function renderReactions(container, state){ let bar = container.querySelector('.reactions'); if (!bar){ bar = document.createElement('div'); bar.className = 'reactions'; container.appendChild(bar); } bar.innerHTML = ''; if (!state) return; const counts = state.counts || {}; const by = state.by || {}; Object.keys(counts).forEach(emoji => { const chip = document.createElement('span'); chip.className = 'reaction-chip'; chip.textContent = emoji + ' ' + counts[emoji]; chip.title = (by[emoji] || []).join(', '); bar.appendChild(chip); }); }
  function createReceiptSpan(){ const span = document.createElement('span'); span.className = 'receipt'; span.textContent = '✅'; return span; }
  function makeEmojiPicker(onPick){ const pop = document.createElement('div'); pop.className = 'emoji-picker'; const grid = document.createElement('div'); grid.className = 'emoji-grid'; ['👍','❤️','😂','🎉','🙏','🔥','😮','😢','👏','😅','🤔','✅'].forEach(e => { const b = document.createElement('button'); b.type='button'; b.className='emoji-btn'; b.textContent=e; b.addEventListener('click', function(){ onPick(e); pop.style.display='none'; }); grid.appendChild(b); }); pop.appendChild(grid); return pop; }

  function attachProfileOpeners(metaEl, name){ const parts = metaEl.textContent.split('•'); const userText = parts[0] ? parts[0].trim() : name; metaEl.textContent = ''; const userLink = document.createElement('a'); userLink.href='#'; userLink.textContent = userText; userLink.className='link-light'; userLink.addEventListener('click', function(e){ e.preventDefault(); socket.emit('get_profile', { username: name }); }); metaEl.appendChild(userLink); if (parts[1]){ const sep = document.createTextNode(' •' + parts[1]); metaEl.appendChild(sep); } }

  let profileCard; function showProfileCard({ username, online, last_seen, email }){ if (profileCard) profileCard.remove(); profileCard = document.createElement('div'); profileCard.className = 'profile-card'; const title=document.createElement('div'); title.className='title'; title.textContent=username; const row1=document.createElement('div'); row1.className='row'; const sLabel=document.createElement('span'); sLabel.textContent='Status'; const sVal=document.createElement('span'); sVal.textContent=online?'Online':'Offline'; if (online) sVal.className='online'; row1.appendChild(sLabel); row1.appendChild(sVal); const row2=document.createElement('div'); row2.className='row'; const lLabel=document.createElement('span'); lLabel.textContent='Last seen'; const lVal=document.createElement('span'); lVal.textContent= last_seen? new Date(last_seen).toLocaleString() : '—'; row2.appendChild(lLabel); row2.appendChild(lVal); const row3=document.createElement('div'); row3.className='row'; const eLabel=document.createElement('span'); eLabel.textContent='Email'; const eVal=document.createElement('span'); eVal.textContent=email||'—'; row3.appendChild(eLabel); row3.appendChild(eVal); const close=document.createElement('button'); close.className='btn btn-sm btn-outline-secondary mt-2'; close.textContent='Close'; close.addEventListener('click', function(){ profileCard.remove(); profileCard=null; }); profileCard.appendChild(title); profileCard.appendChild(row1); profileCard.appendChild(row2); profileCard.appendChild(row3); profileCard.appendChild(close); document.body.appendChild(profileCard); }

  socket.on('profile', function(p){ showProfileCard(p); const meEmailEl=document.getElementById('me-email'); if (p.username===USERNAME && meEmailEl){ meEmailEl.textContent = p.email || '—'; } });

  function addChatMessage({ username, text, timestamp_iso, message_id, reaction_state }) { const row=document.createElement('div'); row.className='message-row' + (username===USERNAME?' own':''); const avatar=document.createElement('div'); avatar.className='avatar'; avatar.textContent=initials(username); const content=document.createElement('div'); content.className='message-content'; const meta=document.createElement('div'); meta.className='message-meta'; meta.textContent = `${username} • ${new Date(timestamp_iso).toLocaleTimeString()}`; attachProfileOpeners(meta, username); const bubble=document.createElement('div'); bubble.className='message-bubble'; bubble.textContent=text; const actions=document.createElement('div'); actions.className='message-actions'; const reactBtn=document.createElement('button'); reactBtn.type='button'; reactBtn.className='btn btn-sm btn-outline-secondary'; reactBtn.textContent='😀'; const picker=makeEmojiPicker(function(emoji){ if (!message_id) return; socket.emit('add_reaction', { room: currentRoom, message_id, emoji }); }); actions.appendChild(reactBtn); actions.appendChild(picker); reactBtn.addEventListener('click', function(e){ e.stopPropagation(); picker.style.display = picker.style.display==='block' ? 'none' : 'block'; }); document.addEventListener('click', function(){ picker.style.display='none'; }); let receipt; if (username===USERNAME){ receipt=createReceiptSpan(); meta.appendChild(document.createTextNode(' ')); meta.appendChild(receipt);} content.appendChild(meta); content.appendChild(bubble); content.appendChild(actions); row.appendChild(avatar); row.appendChild(content); messagesEl.appendChild(row); if (message_id){ messageIdToRow.set(message_id, { row, meta, receipt, reactions: [] }); } if (reaction_state){ renderReactions(content, reaction_state); } scrollToBottom(); }

  socket.on('connect', function () { socket.emit('join_room', { room: currentRoom }); addSystemMessage(`Joined room ${currentRoom} at ${new Date().toLocaleString()}`); touchRecent(currentRoom); socket.emit('get_profile', { username: USERNAME }); });
  socket.on('chat_history', function (payload) { if (payload.room !== currentRoom) return; (payload.messages || []).forEach(addChatMessage); });
  socket.on('room_message', function (msg) { if (msg.room !== currentRoom) return; addChatMessage(msg); });
  socket.on('reaction_state', function(state){ const entry = messageIdToRow.get(state.message_id); if (!entry) return; const content = entry.row.querySelector('.message-content'); content && renderReactions(content, state); });

  // Typing
  let typingDebounce; function sendTyping(isTyping){ socket.emit('typing', { room: currentRoom, is_typing: !!isTyping }); }
  messageForm.addEventListener('input', function(){ if (typingDebounce) clearTimeout(typingDebounce); sendTyping(true); typingDebounce = setTimeout(()=> sendTyping(false), 1200); });

  messageForm.addEventListener('submit', function (e) { e.preventDefault(); const text=messageInput.value.trim(); if (text){ socket.emit('send_message', { room: currentRoom, text }); } messageInput.value=''; });

  // Allow editing code and rejoining from any code field
  function wireCodeInput(el){ if (!el) return; el.addEventListener('input', function(){ const d = digitsOnly(el.value); el.value = d; const other = (el===codeTop? codeSide : codeTop); if (other) other.value = d; }); el.addEventListener('keydown', function(e){ if (e.key==='Enter'){ e.preventDefault(); updateContextToRoom(el.value); } }); el.addEventListener('blur', function(){ updateContextToRoom(el.value); }); }
  wireCodeInput(codeTop); wireCodeInput(codeSide);
})();


