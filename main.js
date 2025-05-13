// Babylon.js 3D Dodge Sandbox - Main Game Logic

// Console output capture
const consoleOutput = document.getElementById('consoleOutput');
const originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn,
    info: console.info
};

function addConsoleMessage(type, args) {
    const line = document.createElement('div');
    line.className = `console-line console-${type}`;
    line.textContent = Array.from(args).join(' ');
    consoleOutput.appendChild(line);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
    while (consoleOutput.children.length > 100) {
        consoleOutput.removeChild(consoleOutput.firstChild);
    }
}

console.log = function() { 
    addConsoleMessage('log', arguments);
    originalConsole.log.apply(console, arguments);
};
console.error = function() {
    addConsoleMessage('error', arguments);
    originalConsole.error.apply(console, arguments);
};
console.warn = function() {
    addConsoleMessage('warn', arguments);
    originalConsole.warn.apply(console, arguments);
};
console.info = function() {
    addConsoleMessage('info', arguments);
    originalConsole.info.apply(console, arguments);
};

// FIRST: Define all constants at the very top of the file, before anything else
const MOUSE_SENSITIVITY = 0.1;
const FORWARD_SPEED = 0.5;
const ROTATION_SMOOTHING = 0.05;
const POSITION_SMOOTHING = 0.02;
const MAX_VELOCITY = 0.5;
const MOUSE_Y_SCALE = 200;
const TAKEOFF_SPEED = 1.2;
const ACCELERATION = 0.02;
const GROUND_FRICTION = 0.01;
const GRAVITY = 0.015;
const LIFT_POWER = 0.03;
const PLANE_HEIGHT = 0.8;
const RUNWAY_HEIGHT = 0.1;
const MIN_FLIGHT_HEIGHT = RUNWAY_HEIGHT + PLANE_HEIGHT;
const MOUSE_SMOOTHING = 0.1;        // How smooth the mouse controls feel
const MAX_PITCH_ANGLE = Math.PI / 4; // Maximum pitch up/down (45 degrees)
const MAX_ROLL_ANGLE = Math.PI / 3;  // Maximum roll left/right (60 degrees)

// SECOND: Your canvas and engine setup
const canvas = document.getElementById('renderCanvas');
const engine = new BABYLON.Engine(canvas, true);
const gameOverOverlay = document.getElementById('gameOverOverlay');
const restartBtn = document.getElementById('restartBtn');

// THIRD: Your state variables
let currentSpeed = 0;
let isAirborne = false;
let isOnRunway = true;
let targetRotationX = 0;
let targetRotationZ = 0;
let currentRotationX = 0;
let currentRotationZ = 0;
let normalizedX = 0;
let normalizedY = 0;
let targetX = 0;
let targetY = MIN_FLIGHT_HEIGHT;
let currentVelocityX = 0;
let currentVelocityY = 0;
let hasStartedTakeoff = false;
let cameraRotationOffset = 180;
let prevMouseX = 0;
let prevMouseY = 0;
let targetPitch = 0;
let targetRoll = 0;
let currentPitch = 0;
let currentRoll = 0;
let planeBody;
let camera;
let buildings = [];

// --- CONFIGURABLE PARAMETERS ---
const TILE_COUNT = 12;
const TILE_LENGTH = 20;
const TILE_WIDTH = 40;
const FLOOR_START_Z = 0;
const BUILDINGS_PER_TILE = 4;
const BUILDING_MIN_HEIGHT = 4;
const BUILDING_MAX_HEIGHT = 16;
const BUILDING_MIN_WIDTH = 2;
const BUILDING_MAX_WIDTH = 5;
const PLAYER_SPEED = 0.6;
const RECYCLE_OFFSET = TILE_COUNT * TILE_LENGTH;
const BOUNDS = 18;
const DEBRIS_COUNT = 16;
const RUNWAY_WIDTH = 20; // Width of the runway (adjust as needed)
const RUNWAY_LENGTH = 1000; // Length of the runway
const RUNWAY_COLOR = new BABYLON.Color3(0, 0, 0); // Black
const MAX_SPEED = 2.0;
const MIN_SPEED = 0.8;
const THROTTLE_CHANGE_RATE = 0.01;
const MOUSE_CONTROL_SENSITIVITY = 0.05; // How responsive the plane is to mouse movement
const PLANE_ROTATION_SMOOTHNESS = 0.1;  // How smoothly the plane rotates (lower = smoother)
const PITCH_SENSITIVITY = 0.05;
const ROLL_SENSITIVITY = 0.05;
const INITIAL_HEIGHT = 20;
const PITCH_EFFECT_ON_SPEED = 0.3;    // How much pitch affects speed
const BANK_ANGLE_MAX = Math.PI / 3;    // Maximum banking angle (60 degrees)
const LIFT_FORCE = 0.02;
const GRAVITY_FORCE = 0.008;
const DRAG_FACTOR = 0.02;              // Air resistance
const TURN_RESPONSIVENESS = 0.08;      // How quickly the plane responds to turning
const PITCH_RESPONSIVENESS = 0.06;     // How quickly the plane responds to pitch changes
const STABILIZATION_SPEED = 0.02;      // How quickly plane returns to level flight
const ROTATION_SCALE = Math.PI / 3;  // How far the plane can rotate
const BUILDING_SPAWN_DISTANCE = 200;
const BUILDING_DESPAWN_DISTANCE = 50;
const BUILDING_SPAWN_INTERVAL = 10;

let gameOver = false;
let debrisPieces = [];
let throttle = 0.5;
let pitch = 0;
let roll = 0;
let yaw = 0;
let lastMouseX = 0;
let lastMouseY = 0;
let bankAngle = 0;
let pitchAngle = 0;
let liftForce = 0;

// Remove any double-click fullscreen logic (if present)
// Add double-click for horizontal flip (barrel roll)
let isFlipping = false;
let flipProgress = 0;
let flipDirection = -1; // -1 for left, 1 for right (default left)
let flipDuration = 1.0; // seconds for a full roll

canvas.addEventListener('dblclick', () => {
    if (isFlipping || gameOver) return;
    isFlipping = true;
    flipProgress = 0;
    flipDirection = -1; // Always left for now
});

function randomBetween(a, b) {
    return a + Math.random() * (b - a);
}

function checkCollision(player, buildings) {
    const playerPos = player.position;
    
    for (const building of buildings) {
        // Skip the green bases in collision check
        if (building.name === 'base') continue;

        // Get building dimensions
        const buildingWidth = building.scaling.x * building.getBoundingInfo().boundingBox.extendSize.x * 2;
        const buildingHeight = building.scaling.y * building.getBoundingInfo().boundingBox.extendSize.y * 2;
        const buildingDepth = building.scaling.z * building.getBoundingInfo().boundingBox.extendSize.z * 2;

        // Calculate distances
        const dx = Math.abs(playerPos.x - building.position.x);
        const dy = Math.abs(playerPos.y - building.position.y);
        const dz = Math.abs(playerPos.z - building.position.z);

        // Check if plane is within building bounds (with small buffer)
        if (dx < buildingWidth/2 + 2 && // Add 2 units buffer for plane size
            dy < buildingHeight/2 + 1 && // Add 1 unit buffer for plane height
            dz < buildingDepth/2 + 2) {  // Add 2 units buffer for plane length
            
            console.log('COLLISION:', {
                playerPos: player.position,
                buildingPos: building.position,
                buildingSize: {
                    width: buildingWidth,
                    height: buildingHeight,
                    depth: buildingDepth
                }
            });
            return true;
        }
    }
    return false;
}

function explodePlayer(player, scene) {
    const debris = [];
    for (let i = 0; i < DEBRIS_COUNT; i++) {
        const size = randomBetween(0.3, 0.7);
        const piece = BABYLON.MeshBuilder.CreateBox('debris', {size}, scene);
        piece.position.copyFrom(player.position);
        piece.position.y += randomBetween(-0.5, 0.5);
        const mat = new BABYLON.StandardMaterial('debrisMat', scene);
        mat.diffuseColor = new BABYLON.Color3(randomBetween(0.2,1), randomBetween(0.2,1), randomBetween(0.2,1));
        piece.material = mat;
        piece._velocity = new BABYLON.Vector3(
            randomBetween(-0.5, 0.5),
            randomBetween(0.2, 1.2),
            randomBetween(-0.5, 0.5)
        );
        debris.push(piece);
    }
    return debris;
}

function spawnBuilding(z, scene) {
    let width = randomBetween(10, 30);
    let depth = randomBetween(10, 30);
    let height = randomBetween(40, 120);

    // Prevent buildings from spawning on the runway
    let x;
    do {
        x = randomBetween(-400, 400);
    } while (Math.abs(x) < RUNWAY_WIDTH / 2 + width / 2);

    // Create building
    let building = BABYLON.MeshBuilder.CreateBox('building', {height, width, depth}, scene);
    building.position.x = x;
    building.position.y = height / 2;
    building.position.z = z;
    let mat = new BABYLON.StandardMaterial('buildingMat', scene);
    mat.diffuseColor = new BABYLON.Color3(randomBetween(0.1,0.7), randomBetween(0.1,0.7), randomBetween(0.1,0.7));
    building.material = mat;

    // Add green base/foundation
    let base = BABYLON.MeshBuilder.CreateBox('base', {
        height: 0.5,
        width: width + 4, // Slightly wider than building
        depth: depth + 4  // Slightly deeper than building
    }, scene);
    base.position.x = x;
    base.position.y = 0.25; // Half of base height
    base.position.z = z;
    let baseMat = new BABYLON.StandardMaterial('baseMat', scene);
    baseMat.diffuseColor = new BABYLON.Color3(0.2, 0.5, 0.2); // Green color
    base.material = baseMat;

    buildings.push(building);
    buildings.push(base);
}

// Plane creation function for different types
function createPlaneModel(type, scene) {
    // Set default flight parameters
    window.PLANE_STATS = {
        MAX_SPEED: 2.0,
        MIN_SPEED: 0.8,
        ACCELERATION: 0.02,
        ROTATION_SMOOTHING: 0.05,
        MAX_PITCH_ANGLE: Math.PI / 4,
        MAX_ROLL_ANGLE: Math.PI / 3,
        TURN_RESPONSIVENESS: 0.08,
        PITCH_RESPONSIVENESS: 0.06
    };
    let plane, planeMat, wingMat, tailFinMat, cockpitMat, engineMat, wheelMat;
    if (type === 'jet') {
        // Jet: sleek, longer, swept wings
        window.PLANE_STATS.MAX_SPEED = 4.0;
        window.PLANE_STATS.MIN_SPEED = 1.8;
        window.PLANE_STATS.ACCELERATION = 0.04;
        plane = BABYLON.MeshBuilder.CreateBox('planeBody', {height: 0.7, width: 1.1, depth: 6}, scene);
        planeMat = new BABYLON.StandardMaterial('planeMat', scene);
        planeMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.7);
        plane.material = planeMat;
        plane.position.y = RUNWAY_HEIGHT + PLANE_HEIGHT;
        plane.position.z = 5;
        plane.position.x = 0;
        plane.rotation.x = 0.04;
        // Nose
        const nose = BABYLON.MeshBuilder.CreateCylinder('nose', {height: 1.2, diameterTop: 0.05, diameterBottom: 0.7}, scene);
        nose.parent = plane;
        nose.rotation.x = Math.PI / 2;
        nose.position.z = 3.1;
        nose.material = planeMat;
        // Wings (swept)
        wingMat = new BABYLON.StandardMaterial('wingMat', scene);
        wingMat.diffuseColor = new BABYLON.Color3(0.7, 0.7, 0.7);
        const leftWing = BABYLON.MeshBuilder.CreateBox('leftWing', {height: 0.08, width: 4.5, depth: 1.2}, scene);
        leftWing.material = wingMat;
        leftWing.parent = plane;
        leftWing.position.x = -2.3;
        leftWing.position.y = 0.18;
        leftWing.position.z = -0.5;
        leftWing.rotation.z = -0.18;
        leftWing.rotation.y = 0.3;
        const rightWing = BABYLON.MeshBuilder.CreateBox('rightWing', {height: 0.08, width: 4.5, depth: 1.2}, scene);
        rightWing.material = wingMat;
        rightWing.parent = plane;
        rightWing.position.x = 2.3;
        rightWing.position.y = 0.18;
        rightWing.position.z = -0.5;
        rightWing.rotation.z = 0.18;
        rightWing.rotation.y = -0.3;
        // Tail
        tailFinMat = new BABYLON.StandardMaterial('tailFinMat', scene);
        tailFinMat.diffuseColor = new BABYLON.Color3(0.8, 0.2, 0.2);
        const tailFin = BABYLON.MeshBuilder.CreateBox('tailFin', {height: 1.1, width: 0.12, depth: 0.7}, scene);
        tailFin.material = tailFinMat;
        tailFin.parent = plane;
        tailFin.position.z = -2.7;
        tailFin.position.y = 0.5;
        // Cockpit
        cockpitMat = new BABYLON.StandardMaterial('cockpitMat', scene);
        cockpitMat.diffuseColor = new BABYLON.Color3(0.2, 0.8, 1);
        cockpitMat.alpha = 0.5;
        const cockpit = BABYLON.MeshBuilder.CreateBox('cockpit', {height: 0.35, width: 0.7, depth: 1.2}, scene);
        cockpit.material = cockpitMat;
        cockpit.parent = plane;
        cockpit.position.y = 0.32;
        cockpit.position.z = 1.1;
        // Engines (jet style)
        engineMat = new BABYLON.StandardMaterial('engineMat', scene);
        engineMat.diffuseColor = new BABYLON.Color3(0.2, 0.2, 0.2);
        const leftEngine = BABYLON.MeshBuilder.CreateCylinder('leftEngine', {height: 1.1, diameter: 0.32}, scene);
        leftEngine.material = engineMat;
        leftEngine.parent = plane;
        leftEngine.rotation.x = Math.PI / 2;
        leftEngine.position.x = -1.2;
        leftEngine.position.y = -0.28;
        leftEngine.position.z = 0.2;
        const rightEngine = BABYLON.MeshBuilder.CreateCylinder('rightEngine', {height: 1.1, diameter: 0.32}, scene);
        rightEngine.material = engineMat;
        rightEngine.parent = plane;
        rightEngine.rotation.x = Math.PI / 2;
        rightEngine.position.x = 1.2;
        rightEngine.position.y = -0.28;
        rightEngine.position.z = 0.2;
        // Wheels
        wheelMat = new BABYLON.StandardMaterial('wheelMat', scene);
        wheelMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.1);
        const leftWheel = BABYLON.MeshBuilder.CreateCylinder('leftWheel', {diameter: 0.32, height: 0.13}, scene);
        leftWheel.material = wheelMat;
        leftWheel.parent = plane;
        leftWheel.position.x = -1.1;
        leftWheel.position.y = -0.5;
        leftWheel.position.z = -1.2;
        leftWheel.rotation.z = Math.PI / 2;
        const rightWheel = BABYLON.MeshBuilder.CreateCylinder('rightWheel', {diameter: 0.32, height: 0.13}, scene);
        rightWheel.material = wheelMat;
        rightWheel.parent = plane;
        rightWheel.position.x = 1.1;
        rightWheel.position.y = -0.5;
        rightWheel.position.z = -1.2;
        rightWheel.rotation.z = Math.PI / 2;
        const noseWheel = BABYLON.MeshBuilder.CreateCylinder('noseWheel', {diameter: 0.22, height: 0.09}, scene);
        noseWheel.material = wheelMat;
        noseWheel.parent = plane;
        noseWheel.position.x = 0;
        noseWheel.position.y = -0.5;
        noseWheel.position.z = 2.2;
        noseWheel.rotation.z = Math.PI / 2;
    } else if (type === 'stunt') {
        // Stunt: short, wide wings, bright colors
        window.PLANE_STATS.ROTATION_SMOOTHING = 0.12;
        window.PLANE_STATS.MAX_PITCH_ANGLE = Math.PI / 3;
        window.PLANE_STATS.MAX_ROLL_ANGLE = Math.PI / 2;
        window.PLANE_STATS.TURN_RESPONSIVENESS = 0.16;
        window.PLANE_STATS.PITCH_RESPONSIVENESS = 0.13;
        plane = BABYLON.MeshBuilder.CreateBox('planeBody', {height: 0.7, width: 1.3, depth: 3.2}, scene);
        planeMat = new BABYLON.StandardMaterial('planeMat', scene);
        planeMat.diffuseColor = new BABYLON.Color3(1, 0.7, 0.1);
        plane.material = planeMat;
        plane.position.y = RUNWAY_HEIGHT + PLANE_HEIGHT;
        plane.position.z = 5;
        plane.position.x = 0;
        plane.rotation.x = 0.09;
        // Nose
        const nose = BABYLON.MeshBuilder.CreateCylinder('nose', {height: 0.7, diameterTop: 0.1, diameterBottom: 0.7}, scene);
        nose.parent = plane;
        nose.rotation.x = Math.PI / 2;
        nose.position.z = 1.7;
        nose.material = planeMat;
        // Wings (very wide)
        wingMat = new BABYLON.StandardMaterial('wingMat', scene);
        wingMat.diffuseColor = new BABYLON.Color3(0.2, 1, 0.2);
        const leftWing = BABYLON.MeshBuilder.CreateBox('leftWing', {height: 0.12, width: 5.2, depth: 1.1}, scene);
        leftWing.material = wingMat;
        leftWing.parent = plane;
        leftWing.position.x = -2.6;
        leftWing.position.y = 0.18;
        leftWing.rotation.z = -0.08;
        const rightWing = BABYLON.MeshBuilder.CreateBox('rightWing', {height: 0.12, width: 5.2, depth: 1.1}, scene);
        rightWing.material = wingMat;
        rightWing.parent = plane;
        rightWing.position.x = 2.6;
        rightWing.position.y = 0.18;
        rightWing.rotation.z = 0.08;
        // Tail
        tailFinMat = new BABYLON.StandardMaterial('tailFinMat', scene);
        tailFinMat.diffuseColor = new BABYLON.Color3(0.8, 0.2, 0.8);
        const tailFin = BABYLON.MeshBuilder.CreateBox('tailFin', {height: 0.8, width: 0.13, depth: 0.5}, scene);
        tailFin.material = tailFinMat;
        tailFin.parent = plane;
        tailFin.position.z = -1.3;
        tailFin.position.y = 0.4;
        // Cockpit
        cockpitMat = new BABYLON.StandardMaterial('cockpitMat', scene);
        cockpitMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.3);
        cockpitMat.alpha = 0.7;
        const cockpit = BABYLON.MeshBuilder.CreateBox('cockpit', {height: 0.32, width: 0.7, depth: 0.8}, scene);
        cockpit.material = cockpitMat;
        cockpit.parent = plane;
        cockpit.position.y = 0.32;
        cockpit.position.z = 0.7;
        // Engine (single, front)
        engineMat = new BABYLON.StandardMaterial('engineMat', scene);
        engineMat.diffuseColor = new BABYLON.Color3(0.2, 0.2, 0.2);
        const engine = BABYLON.MeshBuilder.CreateCylinder('engine', {height: 0.7, diameter: 0.32}, scene);
        engine.material = engineMat;
        engine.parent = plane;
        engine.rotation.x = Math.PI / 2;
        engine.position.x = 0;
        engine.position.y = -0.28;
        engine.position.z = 1.2;
        // Wheels
        wheelMat = new BABYLON.StandardMaterial('wheelMat', scene);
        wheelMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.1);
        const leftWheel = BABYLON.MeshBuilder.CreateCylinder('leftWheel', {diameter: 0.38, height: 0.13}, scene);
        leftWheel.material = wheelMat;
        leftWheel.parent = plane;
        leftWheel.position.x = -0.8;
        leftWheel.position.y = -0.5;
        leftWheel.position.z = -0.7;
        leftWheel.rotation.z = Math.PI / 2;
        const rightWheel = BABYLON.MeshBuilder.CreateCylinder('rightWheel', {diameter: 0.38, height: 0.13}, scene);
        rightWheel.material = wheelMat;
        rightWheel.parent = plane;
        rightWheel.position.x = 0.8;
        rightWheel.position.y = -0.5;
        rightWheel.position.z = -0.7;
        rightWheel.rotation.z = Math.PI / 2;
        const noseWheel = BABYLON.MeshBuilder.CreateCylinder('noseWheel', {diameter: 0.22, height: 0.09}, scene);
        noseWheel.material = wheelMat;
        noseWheel.parent = plane;
        noseWheel.position.x = 0;
        noseWheel.position.y = -0.5;
        noseWheel.position.z = 1.2;
        noseWheel.rotation.z = Math.PI / 2;
    } else {
        // Classic: current boxy
        plane = BABYLON.MeshBuilder.CreateBox('planeBody', {height: 0.8, width: 1, depth: 4}, scene);
        planeMat = new BABYLON.StandardMaterial('planeMat', scene);
        planeMat.diffuseColor = new BABYLON.Color3(0.2, 0.8, 1);
        plane.material = planeMat;
        plane.position.y = RUNWAY_HEIGHT + PLANE_HEIGHT;
        plane.position.z = 5;
        plane.position.x = 0;
        plane.rotation.x = 0.07;
        // Nose
        const nose = BABYLON.MeshBuilder.CreateCylinder('nose', {height: 1, diameterTop: 0.1, diameterBottom: 0.8}, scene);
        nose.parent = plane;
        nose.rotation.x = Math.PI / 2;
        nose.position.z = 2.2;
        nose.material = planeMat;
        // Main Wings
        wingMat = new BABYLON.StandardMaterial('wingMat', scene);
        wingMat.diffuseColor = new BABYLON.Color3(0.8, 0.8, 0.8);
        const leftWing = BABYLON.MeshBuilder.CreateBox('leftWing', {height: 0.1, width: 3.5, depth: 1.5}, scene);
        leftWing.material = wingMat;
        leftWing.parent = plane;
        leftWing.position.x = -1.8;
        leftWing.position.y = 0.2;
        leftWing.rotation.z = -0.1;
        const rightWing = BABYLON.MeshBuilder.CreateBox('rightWing', {height: 0.1, width: 3.5, depth: 1.5}, scene);
        rightWing.material = wingMat;
        rightWing.parent = plane;
        rightWing.position.x = 1.8;
        rightWing.position.y = 0.2;
        rightWing.rotation.z = 0.1;
        // Vertical Stabilizer (tail fin)
        tailFinMat = new BABYLON.StandardMaterial('tailFinMat', scene);
        tailFinMat.diffuseColor = new BABYLON.Color3(0.8, 0.2, 0.2);
        const tailFin = BABYLON.MeshBuilder.CreateBox('tailFin', {height: 1, width: 0.1, depth: 0.8}, scene);
        tailFin.material = tailFinMat;
        tailFin.parent = plane;
        tailFin.position.z = -1.8;
        tailFin.position.y = 0.4;
        // Horizontal Stabilizers (tail wings)
        const leftStab = BABYLON.MeshBuilder.CreateBox('leftStab', {height: 0.1, width: 1.2, depth: 0.6}, scene);
        const rightStab = BABYLON.MeshBuilder.CreateBox('rightStab', {height: 0.1, width: 1.2, depth: 0.6}, scene);
        leftStab.material = rightStab.material = wingMat;
        leftStab.parent = rightStab.parent = plane;
        leftStab.position.x = -0.6;
        leftStab.position.z = -1.8;
        leftStab.position.y = 0.2;
        rightStab.position.x = 0.6;
        rightStab.position.z = -1.8;
        rightStab.position.y = 0.2;
        // Cockpit (canopy)
        cockpitMat = new BABYLON.StandardMaterial('cockpitMat', scene);
        cockpitMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.3);
        cockpitMat.alpha = 0.5;
        const cockpit = BABYLON.MeshBuilder.CreateBox('cockpit', {height: 0.4, width: 0.6, depth: 1}, scene);
        cockpit.material = cockpitMat;
        cockpit.parent = plane;
        cockpit.position.y = 0.4;
        cockpit.position.z = 0.5;
        // Engine nacelles (one under each wing)
        engineMat = new BABYLON.StandardMaterial('engineMat', scene);
        engineMat.diffuseColor = new BABYLON.Color3(0.2, 0.2, 0.2);
        const leftEngine = BABYLON.MeshBuilder.CreateCylinder('leftEngine', {height: 1.2, diameter: 0.3}, scene);
        const rightEngine = BABYLON.MeshBuilder.CreateCylinder('rightEngine', {height: 1.2, diameter: 0.3}, scene);
        leftEngine.material = rightEngine.material = engineMat;
        leftEngine.parent = rightEngine.parent = plane;
        leftEngine.rotation.x = Math.PI / 2;
        rightEngine.rotation.x = Math.PI / 2;
        leftEngine.position.x = -1;
        leftEngine.position.y = -0.3;
        rightEngine.position.x = 1;
        rightEngine.position.y = -0.3;
        // Simple landing gear (wheels)
        wheelMat = new BABYLON.StandardMaterial('wheelMat', scene);
        wheelMat.diffuseColor = new BABYLON.Color3(0.1, 0.1, 0.1);
        // Main wheels (under wings)
        const leftWheel = BABYLON.MeshBuilder.CreateCylinder('leftWheel', {diameter: 0.4, height: 0.2}, scene);
        leftWheel.material = wheelMat;
        leftWheel.parent = plane;
        leftWheel.position.x = -1.1;
        leftWheel.position.y = -0.5;
        leftWheel.position.z = -0.8;
        leftWheel.rotation.z = Math.PI / 2;
        const rightWheel = BABYLON.MeshBuilder.CreateCylinder('rightWheel', {diameter: 0.4, height: 0.2}, scene);
        rightWheel.material = wheelMat;
        rightWheel.parent = plane;
        rightWheel.position.x = 1.1;
        rightWheel.position.y = -0.5;
        rightWheel.position.z = -0.8;
        rightWheel.rotation.z = Math.PI / 2;
        // Nose wheel
        const noseWheel = BABYLON.MeshBuilder.CreateCylinder('noseWheel', {diameter: 0.3, height: 0.15}, scene);
        noseWheel.material = wheelMat;
        noseWheel.parent = plane;
        noseWheel.position.x = 0;
        noseWheel.position.y = -0.5;
        noseWheel.position.z = 1.5;
        noseWheel.rotation.z = Math.PI / 2;
    }
    return plane;
}

const createScene = () => {
    const scene = new BABYLON.Scene(engine);
    scene.clearColor = new BABYLON.Color3(0.53, 0.81, 0.98); // Bright blue sky

    // Lighting
    const light = new BABYLON.HemisphericLight('light', new BABYLON.Vector3(0, 1, 0), scene);
    light.intensity = 0.9;

    // Infinite ground (won't disappear)
    const ground = BABYLON.MeshBuilder.CreateGround('ground', {
        width: 2000,    // Much wider
        height: 2000,   // Much longer
        subdivisions: 2 // For better performance
    }, scene);
    ground.position.y = 0;
    const groundMat = new BABYLON.StandardMaterial('groundMat', scene);
    groundMat.diffuseColor = new BABYLON.Color3(0.2, 0.5, 0.2); // Green color
    ground.material = groundMat;
    ground.receiveShadows = true;

    // Make ground move with player
    scene.onBeforeRenderObservable.add(() => {
        ground.position.z = planeBody.position.z;
    });

    // --- ADD RUNWAY ---
    const runway = BABYLON.MeshBuilder.CreateBox('runway', {
        width: RUNWAY_WIDTH,
        height: 0.1,
        depth: RUNWAY_LENGTH
    }, scene);
    runway.position.y = 0.05; // Slightly above ground
    runway.position.x = 0;
    runway.position.z = RUNWAY_LENGTH / 2;
    const runwayMat = new BABYLON.StandardMaterial('runwayMat', scene);
    runwayMat.diffuseColor = RUNWAY_COLOR;
    runway.material = runwayMat;

    // --- PLANE MODEL (Reverted to Original) ---
    // Main body (fuselage)
    const selectedPlane = localStorage.getItem('selectedPlane') || 'classic';
    planeBody = createPlaneModel(selectedPlane, scene);

    // Initial camera position (front view of plane)
    camera = new BABYLON.FollowCamera('followCam', 
        new BABYLON.Vector3(0, 5, 25), // Positive Z to stay in front
        scene
    );
    camera.lockedTarget = planeBody;
    camera.radius = 15;
    camera.heightOffset = 2;
    camera.rotationOffset = 180; // 180 degrees to face the plane
    camera.cameraAcceleration = 0.05;
    camera.maxCameraSpeed = 10;

    // Movement
    const inputMap = {};
    scene.actionManager = new BABYLON.ActionManager(scene);
    scene.actionManager.registerAction(new BABYLON.ExecuteCodeAction(BABYLON.ActionManager.OnKeyDownTrigger, evt => {
        inputMap[evt.sourceEvent.key.toLowerCase()] = true;
    }));
    scene.actionManager.registerAction(new BABYLON.ExecuteCodeAction(BABYLON.ActionManager.OnKeyUpTrigger, evt => {
        inputMap[evt.sourceEvent.key.toLowerCase()] = false;
    }));

    // Buildings array for forward-only generation
    let lastBuildingZ = 0;

    // Initial building generation
    let startZ = 50;
    let endZ = planeBody.position.z + BUILDING_SPAWN_DISTANCE;
    for (let z = startZ; z < endZ; z += BUILDING_SPAWN_INTERVAL) {
        spawnBuilding(z, scene);
        lastBuildingZ = z;
    }

    // Enable quaternion rotation for the plane
    planeBody.rotationQuaternion = BABYLON.Quaternion.Identity();

    // Game loop
    scene.onBeforeRenderObservable.add(() => {
        if (gameOver) {
            debrisPieces.forEach(piece => {
                piece.position.addInPlace(piece._velocity);
                piece._velocity.y -= 0.04;
                piece.rotation.x += 0.1;
                piece.rotation.y += 0.1;
            });
            return;
        }

        // On mobile, update normalizedX/Y from window (joystick)
        if (isMobile() && typeof window.normalizedX === 'number' && typeof window.normalizedY === 'number') {
            normalizedX = window.normalizedX;
            normalizedY = window.normalizedY;
            console.log('Game loop normalized:', normalizedX, normalizedY);
        }
        // Always set targetPitch/targetRoll from normalizedX/Y
        targetPitch = BABYLON.Scalar.Clamp(
            -normalizedY * window.PLANE_STATS.MAX_PITCH_ANGLE,
            -window.PLANE_STATS.MAX_PITCH_ANGLE,
            window.PLANE_STATS.MAX_PITCH_ANGLE
        );
        targetRoll = BABYLON.Scalar.Clamp(
            -normalizedX * window.PLANE_STATS.MAX_ROLL_ANGLE,
            -window.PLANE_STATS.MAX_ROLL_ANGLE,
            window.PLANE_STATS.MAX_ROLL_ANGLE
        );
        if (isMobile()) {
            console.log('Game loop pitch/roll:', targetPitch, targetRoll);
        }

        // Smoothly interpolate current rotation to target rotation
        currentPitch = BABYLON.Scalar.Lerp(currentPitch, targetPitch, window.PLANE_STATS.ROTATION_SMOOTHING);
        currentRoll = BABYLON.Scalar.Lerp(currentRoll, targetRoll, window.PLANE_STATS.ROTATION_SMOOTHING);

        // Create rotation quaternion
        const rotationQuaternion = BABYLON.Quaternion.RotationYawPitchRoll(
            0,              // Yaw (we're not changing this)
            currentPitch,   // Pitch (up/down)
            currentRoll     // Roll (left/right)
        );

        // Apply rotation to plane
        planeBody.rotationQuaternion = BABYLON.Quaternion.Slerp(
            planeBody.rotationQuaternion,
            rotationQuaternion,
            window.PLANE_STATS.ROTATION_SMOOTHING
        );

        // In the game loop, animate the flip if active
        if (isFlipping) {
            // Animate roll from 0 to -2*PI (full 360) linearly
            const flipSpeed = engine.getDeltaTime() / 1000; // seconds per frame
            flipProgress += flipSpeed;
            let t = flipProgress / flipDuration;
            if (t > 1) t = 1;
            currentRoll = flipDirection * 2 * Math.PI * t;
            targetRoll = currentRoll;
            if (flipProgress >= flipDuration) {
                isFlipping = false;
                targetRoll = 0;
                currentRoll = 0;
            }
        }

        // Calculate movement based on rotation
        if (isAirborne) {
            // Get the plane's forward direction from its rotation
            const forward = new BABYLON.Vector3(0, 0, 1);
            const rotationMatrix = new BABYLON.Matrix();
            planeBody.rotationQuaternion.toRotationMatrix(rotationMatrix);
            const direction = BABYLON.Vector3.TransformNormal(forward, rotationMatrix);

            // Calculate lift based on current pitch
            const liftMultiplier = 1 + Math.abs(currentPitch) * 0.5; // More lift when pitching up
            const verticalForce = LIFT_FORCE * liftMultiplier - GRAVITY_FORCE;

            // Calculate banking turn effect
            let bankTurnFactor = 0;
            let turnSpeed = 0;
            if (!isFlipping) {
                bankTurnFactor = -currentRoll * 1.5; // Increased from 0.8 for much sharper turns
                turnSpeed = currentSpeed * bankTurnFactor;
                planeBody.position.x += turnSpeed;
            }
            planeBody.position.y += (direction.y * currentSpeed) + verticalForce;
            planeBody.position.z += direction.z * currentSpeed * 0.8; // Reduced forward speed during turns

            // Adjust speed based on pitch and roll
            if (currentPitch < 0) { // Nose down
                currentSpeed = Math.min(currentSpeed + window.PLANE_STATS.ACCELERATION * 2, window.PLANE_STATS.MAX_SPEED);
            } else if (currentPitch > 0) { // Nose up
                currentSpeed = Math.max(currentSpeed - window.PLANE_STATS.ACCELERATION, window.PLANE_STATS.MIN_SPEED);
            }

            // Apply drag based on roll angle (more drag during sharp turns)
            let turnDrag = 0;
            if (!isFlipping) {
                turnDrag = Math.abs(currentRoll) * 0.03;
            }
            currentSpeed = Math.max(window.PLANE_STATS.MIN_SPEED, currentSpeed - DRAG_FACTOR - turnDrag);

            // Increased world bounds for more freedom
            planeBody.position.x = BABYLON.Scalar.Clamp(planeBody.position.x, -1200, 1200);
            planeBody.position.y = BABYLON.Scalar.Clamp(planeBody.position.y, MIN_FLIGHT_HEIGHT, 600);
        }

        // Handle takeoff mechanics and throttle
        if (isMobile() && typeof window.mobileThrottle === 'number') {
            // On mobile, throttle slider sets speed
            currentSpeed = window.PLANE_STATS.MIN_SPEED + (window.PLANE_STATS.MAX_SPEED - window.PLANE_STATS.MIN_SPEED) * window.mobileThrottle;
        } else {
            if (inputMap['w'] || inputMap['arrowup']) {
                currentSpeed = Math.min(currentSpeed + window.PLANE_STATS.ACCELERATION, window.PLANE_STATS.MAX_SPEED);
            } else if (inputMap['s'] || inputMap['arrowdown']) {
                currentSpeed = Math.max(currentSpeed - window.PLANE_STATS.ACCELERATION, window.PLANE_STATS.MIN_SPEED);
            }
        }

        // Check for takeoff
        if (!isAirborne && currentSpeed >= TAKEOFF_SPEED && 
            (normalizedY > 0.1) && isOnRunway) {
            isAirborne = true;
        }

        if (!isAirborne) {
            // Ground movement
            planeBody.position.z += currentSpeed;
            planeBody.position.y = MIN_FLIGHT_HEIGHT;

            isOnRunway = Math.abs(planeBody.position.x) < RUNWAY_WIDTH / 2;
            
            const groundTargetX = BABYLON.Scalar.Clamp(
                normalizedX * (RUNWAY_WIDTH / 2), 
                -RUNWAY_WIDTH / 2, 
                RUNWAY_WIDTH / 2
            );
            if (!isFlipping) {
                planeBody.position.x += (groundTargetX - planeBody.position.x) * 0.1;
            }
            currentRotationX = normalizedY * Math.PI / 12;
            currentRotationZ = -normalizedX * Math.PI / 12;
        } else {
            // Flight movement
            const targetVelocityX = (targetX - planeBody.position.x) * POSITION_SMOOTHING;
            const targetVelocityY = (targetY - planeBody.position.y) * POSITION_SMOOTHING;
            
            if (!isFlipping) {
                currentVelocityX += (targetVelocityX - currentVelocityX) * 0.1;
                planeBody.position.x += currentVelocityX;
            }
            currentVelocityY += (targetVelocityY - currentVelocityY) * 0.1;
            planeBody.position.y += currentVelocityY;
            
            if (currentSpeed >= TAKEOFF_SPEED) {
                planeBody.position.z += currentSpeed;
            } else {
                planeBody.position.y = Math.max(
                    planeBody.position.y - GRAVITY, 
                    MIN_FLIGHT_HEIGHT
                );
                if (planeBody.position.y === MIN_FLIGHT_HEIGHT) {
                    isAirborne = false;
                }
            }
        }

        // Keep plane within bounds
        planeBody.position.x = BABYLON.Scalar.Clamp(planeBody.position.x, -1200, 1200);
        planeBody.position.y = BABYLON.Scalar.Clamp(planeBody.position.y, MIN_FLIGHT_HEIGHT, 600);

        // Building generation and collision remain the same
        while (lastBuildingZ < planeBody.position.z + BUILDING_SPAWN_DISTANCE) {
            lastBuildingZ += BUILDING_SPAWN_INTERVAL;
            spawnBuilding(lastBuildingZ, scene);
        }

        for (let i = buildings.length - 1; i >= 0; i--) {
            if (buildings[i].position.z < planeBody.position.z - BUILDING_DESPAWN_DISTANCE) {
                buildings[i].dispose();
                buildings.splice(i, 1);
            }
        }

        if (checkCollision(planeBody, buildings)) {
            planeBody.visibility = 0;
            debrisPieces = explodePlayer(planeBody, scene);
            gameOver = true;
            
            // Show game over overlay with retry button
            const gameOverOverlay = document.getElementById('gameOverOverlay');
            gameOverOverlay.style.display = 'flex';
        }
    });

    return scene;
};

const scene = createScene();
engine.runRenderLoop(() => {
    if (scene) {  // Make sure scene exists before rendering
    scene.render();
    }
});

window.addEventListener('resize', () => {
    engine.resize();
});

// Restart button logic
if (restartBtn) {
    restartBtn.onclick = () => {
        // Clear debris
        debrisPieces.forEach(piece => piece.dispose());
        debrisPieces = [];

        // Remove all buildings
        buildings.forEach(b => b.dispose());
        buildings.length = 0;
        lastBuildingZ = 0;
        // Regenerate initial buildings
        let startZ = 50;
        let endZ = planeBody.position.z + BUILDING_SPAWN_DISTANCE;
        for (let z = startZ; z < endZ; z += BUILDING_SPAWN_INTERVAL) {
            spawnBuilding(z, scene);
            lastBuildingZ = z;
        }

        // Dispose of the old plane
        planeBody.dispose();
        
        // Recreate the plane
        const selectedPlane = localStorage.getItem('selectedPlane') || 'classic';
        planeBody = createPlaneModel(selectedPlane, scene);

        // Reset game state
        gameOver = false;
        isAirborne = false;
        currentSpeed = 0;
        planeBody.rotationQuaternion = BABYLON.Quaternion.Identity();
        
        // Update camera target
        camera.lockedTarget = planeBody;
        
        // Hide game over overlay
        const gameOverOverlay = document.getElementById('gameOverOverlay');
        gameOverOverlay.style.display = 'none';

        // Reset all scores
        resetAllScores();
        startScore();
    };
}

// Enhanced mouse movement handler
canvas.addEventListener("mousemove", (evt) => {
    if (gameOver) return;
    if (isMobile()) return; // On mobile, joystick sets normalizedX/Y
    
    if (isAirborne) {
        // Get mouse position relative to canvas center
        const rect = canvas.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        // Calculate normalized mouse position (-1 to 1)
        const rawNormalizedX = (evt.clientX - centerX) / (rect.width / 2);
        const rawNormalizedY = (evt.clientY - centerY) / (rect.height / 2);
        // Apply exponential response curve for more precise control
        const expX = Math.sign(rawNormalizedX) * Math.pow(Math.abs(rawNormalizedX), 1.5);
        const expY = Math.sign(rawNormalizedY) * Math.pow(Math.abs(rawNormalizedY), 1.5);
        // Apply smoothing to prevent sudden movements
        normalizedX = BABYLON.Scalar.Lerp(normalizedX, expX, MOUSE_SMOOTHING);
        normalizedY = BABYLON.Scalar.Lerp(normalizedY, expY, MOUSE_SMOOTHING);
        // Calculate target angles with limits
        targetPitch = BABYLON.Scalar.Clamp(
            -normalizedY * window.PLANE_STATS.MAX_PITCH_ANGLE,
            -window.PLANE_STATS.MAX_PITCH_ANGLE,
            window.PLANE_STATS.MAX_PITCH_ANGLE
        );
        targetRoll = BABYLON.Scalar.Clamp(
            -normalizedX * window.PLANE_STATS.MAX_ROLL_ANGLE,
            -window.PLANE_STATS.MAX_ROLL_ANGLE,
            window.PLANE_STATS.MAX_ROLL_ANGLE
        );
        // Add yaw effect when rolling (banking turns)
        const yawAmount = -normalizedX * 0.02; // Small yaw when banking
        planeBody.position.x += currentSpeed * yawAmount;
    } else {
        // On the ground: only allow mouse up (pitch up) to affect takeoff
        const rect = canvas.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const rawNormalizedY = (evt.clientY - centerY) / (rect.height / 2);
        // Only allow pitch up (mouse down, positive Y)
        if (rawNormalizedY > 0) {
            const expY = Math.sign(rawNormalizedY) * Math.pow(Math.abs(rawNormalizedY), 1.5);
            normalizedY = BABYLON.Scalar.Lerp(normalizedY, expY, MOUSE_SMOOTHING);
            targetPitch = BABYLON.Scalar.Clamp(
                -normalizedY * window.PLANE_STATS.MAX_PITCH_ANGLE,
                -window.PLANE_STATS.MAX_PITCH_ANGLE,
                window.PLANE_STATS.MAX_PITCH_ANGLE
            );
        } else {
            targetPitch = 0.07; // Slight nose-up
            normalizedY = 0;
        }
        // Always ignore left/right and down
        targetRoll = 0;
        normalizedX = 0;
    }
});

// Add a simple speedometer to the HTML (optional)
const speedometer = document.createElement('div');
speedometer.id = 'speedometer';
speedometer.style.position = 'absolute';
speedometer.style.top = '20px';
speedometer.style.left = '20px';
speedometer.style.color = 'white';
document.body.appendChild(speedometer);

// Also update the collision check with runway
function checkGroundContact() {
    return planeBody.position.y <= (RUNWAY_HEIGHT + PLANE_HEIGHT);
}

// Add this function to safely handle rotation
function safeRotateAircraft(mesh, pitch, roll, yaw) {
    try {
        if (!mesh || !mesh.rotationQuaternion) return;
        
        // Ensure values are numbers and finite
        pitch = Number.isFinite(pitch) ? pitch : 0;
        roll = Number.isFinite(roll) ? roll : 0;
        yaw = Number.isFinite(yaw) ? yaw : 0;
        
        const rotation = BABYLON.Quaternion.RotationYawPitchRoll(yaw, pitch, roll);
        mesh.rotationQuaternion = rotation;
    } catch (error) {
        console.warn('Error rotating aircraft:', error);
        // Reset to default rotation if there's an error
        mesh.rotationQuaternion = BABYLON.Quaternion.Identity();
    }
}

// Add this function to safely update position
function safeUpdatePosition(mesh, deltaX, deltaY, deltaZ) {
    try {
        if (!mesh || !mesh.position) return;
        
        // Ensure values are numbers and finite
        deltaX = Number.isFinite(deltaX) ? deltaX : 0;
        deltaY = Number.isFinite(deltaY) ? deltaY : 0;
        deltaZ = Number.isFinite(deltaZ) ? deltaZ : 0;
        
        mesh.position.x += deltaX;
        mesh.position.y += deltaY;
        mesh.position.z += deltaZ;
    } catch (error) {
        console.warn('Error updating position:', error);
    }
}

function isMobile() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

// Scoring system
let score = 0;
let highScore = parseInt(localStorage.getItem('highScore') || '0', 10);
let scoreInterval = null;
const scoreDisplay = document.createElement('div');
scoreDisplay.id = 'scoreDisplay';
scoreDisplay.style.position = 'absolute';
scoreDisplay.style.top = '24px';
scoreDisplay.style.right = '32px';
scoreDisplay.style.color = '#fff';
scoreDisplay.style.fontSize = '2.2rem';
scoreDisplay.style.fontFamily = 'Segoe UI, Arial, sans-serif';
scoreDisplay.style.textShadow = '0 2px 8px #000a';
scoreDisplay.style.zIndex = '20';
scoreDisplay.style.background = 'rgba(20,30,40,0.55)';
scoreDisplay.style.padding = '10px 28px';
scoreDisplay.style.borderRadius = '16px';
scoreDisplay.style.letterSpacing = '2px';
scoreDisplay.innerHTML = 'Score: 0<br><span id="highScoreText" style="font-size:1.2rem; color:#ffd700;">High Score: ' + highScore + '</span>';
document.body.appendChild(scoreDisplay);
const highScoreText = document.getElementById('highScoreText');

// Add CSS for high score animation
const style = document.createElement('style');
style.innerHTML = `
@keyframes highScoreGlow {
  0% { color: #ffd700; text-shadow: 0 0 8px #fff700, 0 0 24px #ffd700; transform: scale(1); }
  30% { color: #fff; text-shadow: 0 0 24px #fff, 0 0 48px #ffd700; transform: scale(1.25); }
  60% { color: #ffd700; text-shadow: 0 0 32px #fff700, 0 0 64px #ffd700; transform: scale(1.1); }
  100% { color: #ffd700; text-shadow: 0 0 8px #fff700, 0 0 24px #ffd700; transform: scale(1); }
}
.highscore-animate {
  animation: highScoreGlow 1.2s ease-in-out;
}
`;
document.head.appendChild(style);

// Confetti effect
function showConfetti() {
    const confettiCanvas = document.createElement('canvas');
    confettiCanvas.id = 'confettiCanvas';
    confettiCanvas.style.position = 'fixed';
    confettiCanvas.style.top = '0';
    confettiCanvas.style.left = '0';
    confettiCanvas.style.width = '100vw';
    confettiCanvas.style.height = '100vh';
    confettiCanvas.style.pointerEvents = 'none';
    confettiCanvas.style.zIndex = '9999';
    document.body.appendChild(confettiCanvas);
    confettiCanvas.width = window.innerWidth;
    confettiCanvas.height = window.innerHeight;
    const ctx = confettiCanvas.getContext('2d');
    const confettiCount = 120;
    const confetti = [];
    for (let i = 0; i < confettiCount; i++) {
        confetti.push({
            x: Math.random() * confettiCanvas.width,
            y: Math.random() * -confettiCanvas.height,
            r: 6 + Math.random() * 8,
            d: 8 + Math.random() * 8,
            color: `hsl(${Math.random()*360},90%,60%)`,
            tilt: Math.random() * 10 - 5,
            tiltAngle: 0,
            tiltAngleIncremental: (Math.random() * 0.07) + 0.05
        });
    }
    let frame = 0;
    function drawConfetti() {
        ctx.clearRect(0, 0, confettiCanvas.width, confettiCanvas.height);
        for (let i = 0; i < confetti.length; i++) {
            let c = confetti[i];
            ctx.beginPath();
            ctx.lineWidth = c.r;
            ctx.strokeStyle = c.color;
            ctx.moveTo(c.x + c.tilt + c.r/3, c.y);
            ctx.lineTo(c.x + c.tilt, c.y + c.d);
            ctx.stroke();
        }
        updateConfetti();
        frame++;
        if (frame < 90) {
            requestAnimationFrame(drawConfetti);
        } else {
            confettiCanvas.remove();
        }
    }
    function updateConfetti() {
        for (let i = 0; i < confetti.length; i++) {
            let c = confetti[i];
            c.y += (Math.cos(frame/10) + 3 + c.d/10) * 0.8;
            c.x += Math.sin(frame/15) * 2;
            c.tiltAngle += c.tiltAngleIncremental;
            c.tilt = Math.sin(c.tiltAngle) * 15;
            if (c.y > confettiCanvas.height) {
                c.y = Math.random() * -20;
                c.x = Math.random() * confettiCanvas.width;
            }
        }
    }
    drawConfetti();
}

// Ray burst effect from high score
function showHighScoreRays() {
    const rays = document.createElement('div');
    rays.id = 'highScoreRays';
    rays.style.position = 'absolute';
    rays.style.pointerEvents = 'none';
    rays.style.zIndex = '10000';
    rays.style.left = scoreDisplay.offsetLeft + scoreDisplay.offsetWidth/2 - 100 + 'px';
    rays.style.top = scoreDisplay.offsetTop + scoreDisplay.offsetHeight/2 - 100 + 'px';
    rays.style.width = '200px';
    rays.style.height = '200px';
    rays.innerHTML = Array.from({length: 16}).map((_,i) => `<div class="ray" style="position:absolute; left:50%; top:50%; width:8px; height:80px; background:linear-gradient(180deg,#ffd700 80%,transparent 100%); border-radius:4px; transform:rotate(${i*22.5}deg) translateY(-60px) scaleY(0); opacity:0.7;"></div>`).join('');
    document.body.appendChild(rays);
    setTimeout(() => {
        const rayDivs = rays.querySelectorAll('.ray');
        rayDivs.forEach((ray, idx) => {
            setTimeout(() => {
                ray.style.transition = 'transform 0.7s cubic-bezier(.23,1.12,.72,1.01), opacity 0.7s';
                ray.style.transform = `rotate(${idx*22.5}deg) translateY(-60px) scaleY(1.2)`;
                ray.style.opacity = '0';
            }, idx*20);
        });
        setTimeout(() => { rays.remove(); }, 1200);
    }, 10);
}

function updateScoreDisplay() {
    scoreDisplay.innerHTML = 'Score: ' + score + '<br><span id="highScoreText" style="font-size:1.2rem; color:#ffd700;">High Score: ' + highScore + '</span>';
}

function startScore() {
    if (scoreInterval) clearInterval(scoreInterval);
    score = 0;
    updateScoreDisplay();
    scoreInterval = setInterval(() => {
        if (!gameOver && isAirborne) {
            score++;
            updateScoreDisplay();
        }
    }, 1000);
}

function stopScore() {
    if (scoreInterval) clearInterval(scoreInterval);
    updateScoreDisplay();
}

// Start score when game starts
startScore();

// Stop score on game over and trigger special effects if new high score
scene.onBeforeRenderObservable.add(() => {
    if (gameOver) {
        stopScore();
        if (score > highScore) {
            highScore = score;
            updateHighScore();
            const hsElem = document.getElementById('highScoreText');
            if (hsElem) {
                hsElem.classList.remove('highscore-animate');
                void hsElem.offsetWidth;
                hsElem.classList.add('highscore-animate');
            }
            showConfetti();
            showHighScoreRays();
        }
    }
});

function resetAllScores() {
    score = 0;
    highScore = 0;
    localStorage.removeItem('highScore');
    updateScoreDisplay();
}

// Account system

document.body.appendChild(accountOverlay);

const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const registerBtn = document.getElementById('registerBtn');
const loginBtn = document.getElementById('loginBtn');
const accountMessage = document.getElementById('accountMessage');

let currentUser = null;

// Check for saved login
const savedUser = localStorage.getItem('currentUser');
if (savedUser) {
    const users = JSON.parse(localStorage.getItem('users') || '{}');
    if (users[savedUser]) {
        currentUser = savedUser;
        highScore = users[savedUser].highScore;
        updateScoreDisplay();
        accountOverlay.style.display = 'none';
    }
}

function register() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    if (!username || !password) {
        accountMessage.textContent = 'Please enter both username and password.';
        return;
    }
    const users = JSON.parse(localStorage.getItem('users') || '{}');
    if (users[username]) {
        accountMessage.textContent = 'Username already exists.';
        return;
    }
    users[username] = { password, highScore: 0 };
    localStorage.setItem('users', JSON.stringify(users));
    accountMessage.textContent = 'Registration successful! Please login.';
}

function login() {
    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    if (!username || !password) {
        accountMessage.textContent = 'Please enter both username and password.';
        return;
    }
    const users = JSON.parse(localStorage.getItem('users') || '{}');
    if (!users[username] || users[username].password !== password) {
        accountMessage.textContent = 'Invalid username or password.';
        return;
    }
    currentUser = username;
    localStorage.setItem('currentUser', username);
    highScore = users[username].highScore;
    updateScoreDisplay();
    accountOverlay.style.display = 'none';
    accountMessage.textContent = '';
    socket.emit('user_join', currentUser); // Join chat after login
}

// Game state
let score = 0;
let highScore = 0;
function updateScoreDisplay() {
    // Update score display logic here
}

// Update high score to be user-specific
function updateHighScore() {
    if (currentUser) {
        const users = JSON.parse(localStorage.getItem('users') || '{}');
        users[currentUser].highScore = highScore;
        localStorage.setItem('users', JSON.stringify(users));
    }
}

// Add logout button to the main screen
const mainMenu = document.querySelector('.main-menu'); // Adjust selector based on your HTML
if (mainMenu) {
    const logoutBtn = document.createElement('button');
    logoutBtn.textContent = 'Logout';
    logoutBtn.style.margin = '10px';
    logoutBtn.style.padding = '8px 16px';
    logoutBtn.style.background = '#f44336';
    logoutBtn.style.color = 'white';
    logoutBtn.style.border = 'none';
    logoutBtn.style.borderRadius = '4px';
    logoutBtn.style.cursor = 'pointer';
    logoutBtn.onclick = logout;
    mainMenu.appendChild(logoutBtn);
}

// Wire up logout button in main menu overlay
const mainMenuLogoutBtn = document.getElementById('logoutBtn');
if (mainMenuLogoutBtn) {
    mainMenuLogoutBtn.onclick = logout;
}

// --- Global Chat Logic ---
const chatOverlay = document.getElementById('chatOverlay');
const chatMessagesDiv = document.getElementById('chatMessages');
const chatInput = document.getElementById('chatInput');
const chatSendBtn = document.getElementById('chatSendBtn');
const socket = io('http://localhost:3000'); // <-- moved up here

function loadChatMessages() {
    const messages = JSON.parse(localStorage.getItem('chatMessages') || '[]');
    chatMessagesDiv.innerHTML = messages.map(msg => `<div style='margin-bottom:6px;'><b style='color:#90caf9;'>${msg.user}</b>: <span style='color:#fff;'>${msg.text}</span></div>`).join('');
    chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight;
}

function sendChatMessage() {
    if (!currentUser) {
        alert('You must be logged in to chat!');
        return;
    }
    const text = chatInput.value.trim();
    if (!text) return;
    socket.emit('chat message', text); // Send only the text
    chatInput.value = '';
}

chatSendBtn.onclick = sendChatMessage;
chatInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') sendChatMessage();
});
window.addEventListener('storage', e => {
    if (e.key === 'chatMessages') loadChatMessages();
});
loadChatMessages();

// Listen for messages from the server
socket.on('chat message', (msg) => {
    // msg is now an object: { username, content, timestamp }
    const chatDiv = document.createElement('div');
    chatDiv.innerHTML = `<b style='color:#90caf9;'>${msg.username}</b>: <span style='color:#fff;'>${msg.content}</span>`;
    chatMessagesDiv.appendChild(chatDiv);
    chatMessagesDiv.scrollTop = chatMessagesDiv.scrollHeight;
}); 