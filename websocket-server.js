const WebSocket = require('ws');
const http = require('http');

const server = http.createServer();
const wss = new WebSocket.Server({ server });

// Game state
const rooms = new Map();
const playerConnections = new Map();

// Generate 4-digit room code
function generateRoomId() {
  return Math.random().toString(36).substr(2, 4).toUpperCase();
}

// Create initial room
function createRoom(hostId, settings) {
  const roomId = generateRoomId();
  const room = {
    id: roomId,
    hostId,
    players: [],
    gameState: 'waiting',
    currentRound: 0,
    settings,
    roundStartTime: null,
    roundEvents: []
  };
  rooms.set(roomId, room);
  return room;
}

// Add player to room
function addPlayerToRoom(roomId, playerId, playerName, isHost = false) {
  const room = rooms.get(roomId);
  if (!room || room.players.length >= 4) return null;

  const player = {
    id: playerId,
    name: playerName,
    timeRemaining: room.settings.initialTime,
    score: 0,
    isActive: false,
    hasFolded: false,
    isHost,
    isConnected: true
  };

  room.players.push(player);
  return room;
}

// Broadcast to all players in room
function broadcastToRoom(roomId, message) {
  const room = rooms.get(roomId);
  if (!room) return;

  room.players.forEach(player => {
    const ws = playerConnections.get(player.id);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  });
}

// Start game timer
function startGameTimer(roomId) {
  const room = rooms.get(roomId);
  if (!room || room.gameState !== 'playing') return;

  const interval = setInterval(() => {
    const currentRoom = rooms.get(roomId);
    if (!currentRoom || currentRoom.gameState !== 'playing') {
      clearInterval(interval);
      return;
    }

    // Update timers
    let activePlayers = [];
    const events = [...currentRoom.roundEvents];
    
    currentRoom.players.forEach(player => {
      if (player.isActive && !player.hasFolded && player.timeRemaining > 0) {
        player.timeRemaining -= 1;
        if (player.timeRemaining <= 0) {
          player.isActive = false;
          player.hasFolded = true;
          events.push(`${player.name} ran out of time`);
        } else {
          activePlayers.push(player);
        }
      }
    });

    currentRoom.roundEvents = events;

    // Check if round should end
    if (activePlayers.length <= 1) {
      clearInterval(interval);
      
      const winner = activePlayers[0];
      if (winner) {
        winner.score += 1;
        currentRoom.roundEvents.push(`${winner.name} wins the round!`);
      }

      currentRoom.currentRound += 1;
      currentRoom.gameState = currentRoom.currentRound >= currentRoom.settings.totalRounds ? 'gameEnd' : 'roundEnd';
    }

    // Broadcast update
    broadcastToRoom(roomId, {
      type: 'game_update',
      payload: currentRoom
    });
  }, 1000);
}

wss.on('connection', (ws) => {
  console.log('New WebSocket connection');

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);
      const { type, payload, roomId, playerId } = message;

      switch (type) {
        case 'join':
          if (payload.isHost) {
            // Create new room
            const room = createRoom(playerId, payload.settings);
            addPlayerToRoom(room.id, playerId, payload.playerName, true);
            playerConnections.set(playerId, ws);
            
            ws.send(JSON.stringify({
              type: 'game_update',
              payload: room
            }));
          } else {
            // Join existing room
            const room = addPlayerToRoom(roomId, playerId, payload.playerName);
            if (room) {
              playerConnections.set(playerId, ws);
              broadcastToRoom(roomId, {
                type: 'game_update',
                payload: room
              });
            } else {
              ws.send(JSON.stringify({
                type: 'error',
                payload: { message: 'Room not found or full' }
              }));
            }
          }
          break;

        case 'start_game':
          const gameRoom = rooms.get(roomId);
          if (gameRoom && gameRoom.hostId === playerId) {
            gameRoom.gameState = 'playing';
            gameRoom.roundStartTime = Date.now();
            gameRoom.roundEvents = [];
            gameRoom.players.forEach(player => {
              player.isActive = player.timeRemaining > 0;
              player.hasFolded = false;
            });
            
            broadcastToRoom(roomId, {
              type: 'game_update',
              payload: gameRoom
            });
            
            startGameTimer(roomId);
          }
          break;

        case 'start_round':
          const roundRoom = rooms.get(roomId);
          if (roundRoom && roundRoom.hostId === playerId) {
            // Check for auto-win scenario
            const playersWithTime = roundRoom.players.filter(p => p.timeRemaining > 0);
            
            if (playersWithTime.length === 1) {
              const winner = playersWithTime[0];
              const remainingRounds = roundRoom.settings.totalRounds - roundRoom.currentRound;
              winner.score += remainingRounds;
              roundRoom.currentRound = roundRoom.settings.totalRounds;
              roundRoom.gameState = 'gameEnd';
              roundRoom.roundEvents = [`${winner.name} wins all remaining ${remainingRounds} rounds automatically!`];
            } else {
              roundRoom.gameState = 'playing';
              roundRoom.roundStartTime = Date.now();
              roundRoom.roundEvents = [];
              roundRoom.players.forEach(player => {
                player.isActive = player.timeRemaining > 0;
                player.hasFolded = false;
              });
              startGameTimer(roomId);
            }
            
            broadcastToRoom(roomId, {
              type: 'game_update',
              payload: roundRoom
            });
          }
          break;

        case 'fold':
          const foldRoom = rooms.get(roomId);
          if (foldRoom) {
            const player = foldRoom.players.find(p => p.id === playerId);
            if (player && player.isActive && !player.hasFolded) {
              player.hasFolded = true;
              player.isActive = false;
              foldRoom.roundEvents.push(`${player.name} folded`);
              
              // Check if round should end
              const activePlayers = foldRoom.players.filter(p => p.isActive && !p.hasFolded);
              if (activePlayers.length <= 1) {
                const winner = activePlayers[0];
                if (winner) {
                  winner.score += 1;
                  foldRoom.roundEvents.push(`${winner.name} wins the round!`);
                }
                
                foldRoom.currentRound += 1;
                foldRoom.gameState = foldRoom.currentRound >= foldRoom.settings.totalRounds ? 'gameEnd' : 'roundEnd';
              }
              
              broadcastToRoom(roomId, {
                type: 'game_update',
                payload: foldRoom
              });
            }
          }
          break;
      }
    } catch (error) {
      console.error('Error processing message:', error);
      ws.send(JSON.stringify({
        type: 'error',
        payload: { message: 'Invalid message format' }
      }));
    }
  });

  ws.on('close', () => {
    console.log('WebSocket connection closed');
    // Clean up player connections
    for (const [playerId, connection] of playerConnections.entries()) {
      if (connection === ws) {
        playerConnections.delete(playerId);
        
        // Mark player as disconnected in all rooms
        for (const room of rooms.values()) {
          const player = room.players.find(p => p.id === playerId);
          if (player) {
            player.isConnected = false;
            broadcastToRoom(room.id, {
              type: 'game_update',
              payload: room
            });
          }
        }
        break;
      }
    }
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`WebSocket server running on port ${PORT}`);
});