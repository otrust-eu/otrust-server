// otrust/server.js – PRODUCTION-READY PROTOCOL FOR DISTRIBUTED TRUTH

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const Ajv = require('ajv');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const levelup = require('levelup');
const leveldown = require('leveldown');
const merkle = require('merkle');
const winston = require('winston');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Initialize logger
const logDir = process.env.LOG_DIR || 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logDir, 'combined.log') }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Initialize MongoDB connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/otrust', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
    });
    logger.info(`MongoDB Connected: ${conn.connection.host}`);
    
    // Create indexes for better performance
    await Claim.createIndexes();
    await User.createIndexes();
    
    return conn;
  } catch (error) {
    logger.error(`Error connecting to MongoDB: ${error.message}`);
    // Exit process with failure
    process.exit(1);
  }
};

// Initialize LevelDB for blockchain
const blockchainPath = process.env.BLOCKCHAIN_PATH || './blockchain';
if (!fs.existsSync(blockchainPath)) {
  fs.mkdirSync(blockchainPath, { recursive: true });
}

const blockchainDB = levelup(leveldown(blockchainPath));

// Initialize Express app
const app = express();

// Security settings
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
    },
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'same-origin' }
}));

// Enable CORS with proper configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// Request logging
const accessLogStream = fs.createWriteStream(
  path.join(logDir, 'access.log'),
  { flags: 'a' }
);
app.use(morgan('combined', { stream: accessLogStream }));

// Body parser with limits to prevent DOS
app.use(bodyParser.json({ 
  limit: process.env.REQUEST_SIZE_LIMIT || '1mb',
  extended: true
}));

// Compress responses
app.use(compression());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW || 15 * 60 * 1000, // Default: 15 minutes
  max: process.env.RATE_LIMIT_MAX || 100, // Default: 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later',
  skip: (req) => {
    // Skip rate limiting for requests with valid API tokens
    // Implementation depends on your authentication method
    return req.headers.authorization && req.headers.authorization.startsWith('Bearer ');
  }
});

// Apply rate limiting to all API routes
app.use('/api/', apiLimiter);

// Define MongoDB Schemas with proper validation and indexes
const ClaimSchema = new mongoose.Schema({
  id: { 
    type: String, 
    unique: true, 
    required: true,
    index: true
  },
  claim: { 
    type: String, 
    required: true,
    index: true 
  },
  evidence: { 
    type: [String], 
    required: true,
    validate: {
      validator: function(v) {
        return Array.isArray(v) && v.length > 0;
      },
      message: props => `Evidence must be a non-empty array`
    }
  },
  signature: { 
    type: String, 
    required: true 
  },
  publicKey: { 
    type: String, 
    required: true,
    index: true 
  },
  type: { 
    type: String, 
    required: true,
    index: true 
  },
  parent_id: { 
    type: String, 
    default: null,
    index: true 
  },
  timestamp: { 
    type: Number, 
    required: true,
    index: true 
  },
  semantic: {
    subject: { 
      type: String, 
      required: true,
      index: true 
    },
    predicate: { 
      type: String, 
      required: true,
      index: true 
    },
    object: { 
      type: String, 
      required: true,
      index: true 
    }
  },
  proofChain: [{
    claimId: String,
    action: {
      type: String,
      enum: ['confirmed', 'disputed', 'invalidated'],
      required: true
    },
    signature: { 
      type: String, 
      required: true 
    },
    publicKey: { 
      type: String, 
      required: true 
    },
    timestamp: { 
      type: Number, 
      required: true 
    },
    reason: String,
    confidence: {
      type: Number,
      min: 0,
      max: 1
    }
  }],
  version: { 
    type: Number, 
    default: 1 
  },
  history: { 
    type: Array, 
    default: [] 
  },
  credibilityScore: { 
    type: Number, 
    default: 0,
    index: true 
  },
  blockchainRef: {
    transactionId: String,
    blockHash: String,
    blockIndex: Number,
    timestamp: Number
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    expires: process.env.DATA_RETENTION_DAYS ? (process.env.DATA_RETENTION_DAYS * 86400) : null 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
}, { timestamps: true });

// Create compound indexes for performance
ClaimSchema.index({ 'semantic.subject': 1, 'semantic.predicate': 1, 'semantic.object': 1 });
ClaimSchema.index({ publicKey: 1, timestamp: -1 });
ClaimSchema.index({ credibilityScore: -1, timestamp: -1 });

// Virtual fields
ClaimSchema.virtual('confirmations').get(function() {
  return this.proofChain.filter(p => p.action === 'confirmed').length;
});

ClaimSchema.virtual('disputes').get(function() {
  return this.proofChain.filter(p => p.action === 'disputed').length;
});

// Add instance methods
ClaimSchema.methods.isVerified = function() {
  return this.confirmations > this.disputes && this.blockchainRef;
};

ClaimSchema.methods.calculateCredibility = async function() {
  // Calculate based on confirmation/dispute ratio and contributor reputation
  const confirmedCount = this.proofChain.filter(p => p.action === 'confirmed').length;
  const disputedCount = this.proofChain.filter(p => p.action === 'disputed').length;
  
  // Start with a baseline from the confirmation ratio
  let score = confirmedCount > 0 ? 
    (confirmedCount / (confirmedCount + disputedCount + 1)) * 10 : 0;
  
  // Add bonus for blockchain verification
  if (this.blockchainRef && this.blockchainRef.blockHash) {
    score += 2;
  }
  
  // Weighted by contributor reputation if possible
  try {
    const author = await User.findOne({ publicKey: this.publicKey });
    if (author) {
      // Author reputation influences baseline score
      score = score * (0.5 + (Math.min(author.score, 100) / 200));
    }
    
    // Get average reputation of confirmers
    const confirmerKeys = this.proofChain
      .filter(p => p.action === 'confirmed')
      .map(p => p.publicKey);
    
    if (confirmerKeys.length > 0) {
      const confirmers = await User.find({ publicKey: { $in: confirmerKeys } });
      const avgConfirmerScore = confirmers.reduce((sum, user) => sum + user.score, 0) / 
        (confirmers.length || 1);
      
      // Adjuste score based on confirmer reputation
      score += Math.min(avgConfirmerScore / 20, 3);
    }
  } catch (error) {
    logger.error(`Error calculating credibility: ${error.message}`);
  }
  
  // Update the stored score
  this.credibilityScore = Math.max(0, Math.min(score, 20));
  await this.save();
  
  return {
    score: this.credibilityScore,
    confirmations: confirmedCount,
    disputes: disputedCount,
    verifiedOnChain: !!this.blockchainRef
  };
};

// Set up middleware for automatic timestamp update
ClaimSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const UserSchema = new mongoose.Schema({
  publicKey: { 
    type: String, 
    unique: true, 
    required: true,
    index: true
  },
  displayName: { 
    type: String,
    trim: true
  },
  email: {
    type: String,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please enter a valid email address'
    ],
    sparse: true
  },
  score: { 
    type: Number, 
    default: 0,
    index: true
  },
  verified: { 
    type: Number, 
    default: 0 
  },
  disputed: { 
    type: Number, 
    default: 0 
  },
  created_at: { 
    type: Date, 
    default: Date.now 
  },
  lastActive: {
    type: Date,
    default: Date.now
  },
  claims: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Claim' 
  }],
  proofs: [{
    claimId: String,
    action: String,
    timestamp: Number
  }],
  role: {
    type: String,
    enum: ['user', 'moderator', 'admin'],
    default: 'user'
  }
}, { timestamps: true });

// User indexes for performance
UserSchema.index({ score: -1 });
UserSchema.index({ created_at: -1 });

// Update last active timestamp
UserSchema.methods.updateActivity = async function() {
  this.lastActive = Date.now();
  await this.save();
};

const Claim = mongoose.model('Claim', ClaimSchema);
const User = mongoose.model('User', UserSchema);

// JSON Schema validation with Ajv
const ajv = new Ajv({ allErrors: true });

const claimSchema = {
  type: 'object',
  properties: {
    claim: { 
      type: 'string',
      minLength: 3,
      maxLength: 5000
    },
    evidence: { 
      type: 'array', 
      items: { 
        type: 'string',
        format: 'uri'
      },
      minItems: 1
    },
    signature: { type: 'string' },
    publicKey: { type: 'string' },
    type: { 
      type: 'string',
      enum: ['factual', 'opinion', 'analysis', 'reference']
    },
    parent_id: { 
      type: ['string', 'null']
    },
    timestamp: { type: 'number' },
    semantic: {
      type: 'object',
      properties: {
        subject: { 
          type: 'string',
          minLength: 1,
          maxLength: 500
        },
        predicate: { 
          type: 'string',
          minLength: 1,
          maxLength: 500
        },
        object: { 
          type: 'string',
          minLength: 1,
          maxLength: 500
        }
      },
      required: ['subject', 'predicate', 'object']
    }
  },
  required: ['claim', 'evidence', 'signature', 'publicKey', 'type', 'timestamp', 'semantic'],
  additionalProperties: false
};

const proofSchema = {
  type: 'object',
  properties: {
    claimId: { type: 'string' },
    action: { 
      type: 'string', 
      enum: ['confirmed', 'disputed', 'invalidated'] 
    },
    signature: { type: 'string' },
    publicKey: { type: 'string' },
    timestamp: { type: 'number' },
    reason: { 
      type: 'string',
      maxLength: 1000
    },
    confidence: { 
      type: 'number', 
      minimum: 0, 
      maximum: 1 
    }
  },
  required: ['claimId', 'action', 'signature', 'publicKey', 'timestamp'],
  additionalProperties: false
};

// Add formats for better validation
ajv.addFormat('uri', (str) => {
  try {
    new URL(str);
    return true;
  } catch (e) {
    return false;
  }
});

// Compile schemas
const validateClaim = ajv.compile(claimSchema);
const validateProof = ajv.compile(proofSchema);

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    // Check for token in header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization required' });
    }
    
    // Extract token
    const token = authHeader.split(' ')[1];
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-default-secret-key');
    
    // Find user by publicKey
    const user = await User.findOne({ publicKey: decoded.publicKey });
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Update last active timestamp
    await user.updateActivity();
    
    // Attach user to request
    req.user = user;
    
    next();
  } catch (error) {
    logger.error(`Authentication error: ${error.message}`);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Admin-only middleware
const adminOnly = async (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
  }
  next();
};

// Lightweight Blockchain Implementation
class Block {
  constructor(index, timestamp, data, previousHash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.nonce = 0;
    this.hash = this.calculateHash();
    this.merkleRoot = this.calculateMerkleRoot();
  }

  calculateHash() {
    return crypto.createHash('sha256')
      .update(this.index + this.timestamp + JSON.stringify(this.data) + this.previousHash + this.nonce)
      .digest('hex');
  }

  calculateMerkleRoot() {
    if (!Array.isArray(this.data) || this.data.length === 0) {
      return crypto.createHash('sha256').update('empty').digest('hex');
    }
    
    const tree = merkle('sha256').sync(this.data.map(item => JSON.stringify(item)));
    return tree.root();
  }

  // Lightweight proof-of-work
  mineBlock(difficulty) {
    const target = Array(difficulty + 1).join('0');
    
    let startTime = Date.now();
    
    while (this.hash.substring(0, difficulty) !== target) {
      this.nonce++;
      this.hash = this.calculateHash();
      
      // Add timeout to prevent hanging on high difficulty
      if (Date.now() - startTime > 60000) { // 1 minute timeout
        logger.warn(`Mining timeout for block ${this.index}. Reducing difficulty.`);
        difficulty = Math.max(1, difficulty - 1);
        startTime = Date.now();
      }
    }
    
    logger.info(`Block mined: ${this.hash}`);
    return this.hash;
  }

  // Validate block integrity
  isValid() {
    // Rehash to check if tampering occurred
    const calculatedHash = this.calculateHash();
    if (calculatedHash !== this.hash) {
      return false;
    }
    
    // Verify merkle root
    const calculatedRoot = this.calculateMerkleRoot();
    if (calculatedRoot !== this.merkleRoot) {
      return false;
    }
    
    return true;
  }
}

class Blockchain {
  constructor() {
    this.chain = [];
    this.difficulty = parseInt(process.env.BLOCKCHAIN_DIFFICULTY) || 2;
    this.pendingTransactions = [];
    this.blockSize = parseInt(process.env.BLOCKCHAIN_BLOCK_SIZE) || 10;
    this.initialized = false;
    this.miningBusy = false;
    
    // Use worker thread for mining in production
    this.useWorker = process.env.NODE_ENV === 'production';
  }

  async initialize() {
    try {
      // Try to load existing blockchain from LevelDB
      const chainData = await blockchainDB.get('chain').catch(() => null);
      
      if (chainData) {
        this.chain = JSON.parse(chainData.toString());
        logger.info(`Loaded blockchain with ${this.chain.length} blocks`);
      } else {
        // If no chain exists, create genesis block
        await this.createGenesisBlock();
      }
      
      this.initialized = true;
      
      // Start periodic mining of pending transactions
      if (process.env.AUTO_MINE === 'true') {
        this.startPeriodicMining();
      }
    } catch (error) {
      logger.error(`Failed to initialize blockchain: ${error.message}`);
      // If something goes wrong, create genesis block
      await this.createGenesisBlock();
      this.initialized = true;
    }
  }

  async createGenesisBlock() {
    const genesisBlock = new Block(
      0, 
      Date.now(), 
      [{ 
        type: 'genesis', 
        data: 'OTRUST Genesis Block', 
        timestamp: Date.now() 
      }], 
      '0'
    );
    
    genesisBlock.mineBlock(this.difficulty);
    this.chain = [genesisBlock];
    await this.saveChain();
    logger.info('Genesis block created');
  }

  async saveChain() {
    // Only save latest 100 blocks to LevelDB to prevent it from growing too large
    const chainToSave = this.chain.slice(-100);
    await blockchainDB.put('chain', JSON.stringify(chainToSave));
    
    // Archive older blocks if needed
    if (this.chain.length > 100 && process.env.ARCHIVE_BLOCKCHAIN === 'true') {
      const blocksToArchive = this.chain.slice(0, -100);
      
      // Archive blocks in batches
      for (let i = 0; i < blocksToArchive.length; i += 10) {
        const batch = blocksToArchive.slice(i, i + 10);
        await blockchainDB.put(`archive_${batch[0].index}_${batch[batch.length-1].index}`, 
          JSON.stringify(batch));
      }
      
      // Update in-memory chain to only keep latest 100 blocks
      this.chain = chainToSave;
    }
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  async addTransaction(transaction) {
    // Wait until blockchain is initialized
    await this.waitForInitialization();
    
    // Validate transaction
    if (!transaction.id || !transaction.type) {
      throw new Error('Invalid transaction structure');
    }
    
    // Add timestamp if not present
    if (!transaction.timestamp) {
      transaction.timestamp = Date.now();
    }
    
    // Add hash if not present
    if (!transaction.hash) {
      transaction.hash = crypto.createHash('sha256')
        .update(JSON.stringify(transaction))
        .digest('hex');
    }
    
    this.pendingTransactions.push(transaction);
    
    // If we have enough transactions, mine a new block
    if (this.pendingTransactions.length >= this.blockSize) {
      await this.mineNewBlock();
    }
    
    return this.pendingTransactions.length;
  }

  async waitForInitialization() {
    // Wait until blockchain is initialized
    const timeout = Date.now() + 30000; // 30 second timeout
    while (!this.initialized) {
      if (Date.now() > timeout) {
        throw new Error('Blockchain initialization timeout');
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  async mineNewBlock() {
    // Prevent concurrent mining
    if (this.miningBusy) {
      logger.info('Mining already in progress, skipping');
      return null;
    }
    
    this.miningBusy = true;
    
    try {
      // Create a copy of pending transactions
      const transactionsToAdd = [...this.pendingTransactions];
      if (transactionsToAdd.length === 0) {
        this.miningBusy = false;
        return null;
      }
      
      this.pendingTransactions = [];
      
      const latestBlock = this.getLatestBlock();
      const newBlock = new Block(
        this.chain.length,
        Date.now(),
        transactionsToAdd,
        latestBlock.hash
      );
      
      logger.info(`Mining block ${newBlock.index} with ${transactionsToAdd.length} transactions...`);
      
      // Mine the block (potentially in a worker thread in production)
      if (this.useWorker) {
        // Here you would implement worker thread mining
        // For simplicity, we're still doing it synchronously
        newBlock.mineBlock(this.difficulty);
      } else {
        newBlock.mineBlock(this.difficulty);
      }
      
      // Validate and add the new block
      if (this.validateNewBlock(newBlock, latestBlock)) {
        this.chain.push(newBlock);
        await this.saveChain();
        
        // Adjust difficulty if needed
        this.adjustDifficulty();
        
        logger.info(`Block ${newBlock.index} mined successfully`);
        this.miningBusy = false;
        return newBlock;
      } else {
        logger.error(`Invalid block generated: ${newBlock.index}`);
        // Put transactions back in pending queue
        this.pendingTransactions = [...transactionsToAdd, ...this.pendingTransactions];
        this.miningBusy = false;
        return null;
      }
    } catch (error) {
      logger.error(`Error mining new block: ${error.message}`);
      this.miningBusy = false;
      return null;
    }
  }

  validateNewBlock(newBlock, previousBlock) {
    // Check block structure
    if (!newBlock.hash || typeof newBlock.hash !== 'string') {
      logger.error('Invalid block hash');
      return false;
    }
    
    // Check block hash
    if (newBlock.hash !== newBlock.calculateHash()) {
      logger.error('Invalid block hash calculation');
      return false;
    }
    
    // Check previous hash
    if (newBlock.previousHash !== previousBlock.hash) {
      logger.error('Invalid previous hash reference');
      return false;
    }
    
    // Check block index
    if (newBlock.index !== previousBlock.index + 1) {
      logger.error('Invalid block index');
      return false;
    }
    
    // Check merkle root
    if (newBlock.merkleRoot !== newBlock.calculateMerkleRoot()) {
      logger.error('Invalid merkle root');
      return false;
    }
    
    return true;
  }

  async forceNewBlock() {
    // Force a new block even if it's not full
    if (this.pendingTransactions.length > 0) {
      return await this.mineNewBlock();
    }
    return null;
  }

  isChainValid() {
    // Validate the entire blockchain
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];
      
      // Validate block integrity
      if (!currentBlock.isValid()) {
        return false;
      }
      
      // Validate chain links
      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }
    return true;
  }

  adjustDifficulty() {
    // Adjust mining difficulty based on block generation times
    if (this.chain.length < 3) return;
    
    const latestBlock = this.getLatestBlock();
    const previousBlock = this.chain[this.chain.length - 2];
    
    // Calculate time difference between blocks
    const timeDiff = latestBlock.timestamp - previousBlock.timestamp;
    
    // Target block time (in ms)
    const targetTime = process.env.TARGET_BLOCK_TIME || 30000; // 30 seconds
    
    // If blocks are being generated too quickly, increase difficulty
    if (timeDiff < targetTime / 2) {
      this.difficulty = Math.min(this.difficulty + 1, 5);
      logger.info(`Increased mining difficulty to ${this.difficulty}`);
    }
    // If blocks are being generated too slowly, decrease difficulty
    else if (timeDiff > targetTime * 2) {
      this.difficulty = Math.max(this.difficulty - 1, 1);
      logger.info(`Decreased mining difficulty to ${this.difficulty}`);
    }
  }

  async getBlockByHash(hash) {
    // Try to find the block in the main chain
    const block = this.chain.find(block => block.hash === hash);
    if (block) return block;
    
    // If not found in main chain, check archives
    try {
      // Get list of archive keys
      const keys = await new Promise((resolve, reject) => {
        const keys = [];
        blockchainDB.createKeyStream({ gt: 'archive_', lt: 'archive_\uffff' })
          .on('data', key => keys.push(key.toString()))
          .on('error', reject)
          .on('end', () => resolve(keys));
      });
      
      // Search archives
      for (const key of keys) {
        const archivedBlocks = JSON.parse((await blockchainDB.get(key)).toString());
        const foundBlock = archivedBlocks.find(block => block.hash === hash);
        if (foundBlock) return foundBlock;
      }
    } catch (error) {
      logger.error(`Error searching archived blocks: ${error.message}`);
    }
    
    return null;
  }

  async getTransactionInChain(transactionId) {
    // Search in the main chain first
    for (const block of this.chain) {
      const found = block.data.find(tx => tx.id === transactionId);
      if (found) {
        return {
          transaction: found,
          blockHash: block.hash,
          blockIndex: block.index,
          timestamp: block.timestamp
        };
      }
    }
    
    // If not found in main chain, check archives
    try {
      // Get list of archive keys
      const keys = await new Promise((resolve, reject) => {
        const keys = [];
        blockchainDB.createKeyStream({ gt: 'archive_', lt: 'archive_\uffff' })
          .on('data', key => keys.push(key.toString()))
          .on('error', reject)
          .on('end', () => resolve(keys));
      });
      
      // Search archives
      for (const key of keys) {
        const archivedBlocks = JSON.parse((await blockchainDB.get(key)).toString());
        
        for (const block of archivedBlocks) {
          const found = block.data.find(tx => tx.id === transactionId);
          if (found) {
            return {
              transaction: found,
              blockHash: block.hash,
              blockIndex: block.index,
              timestamp: block.timestamp
            };
          }
        }
      }
    } catch (error) {
      logger.error(`Error searching archived blocks for transaction: ${error.message}`);
    }
    
    return null;
  }

  startPeriodicMining() {
    const interval = process.env.MINING_INTERVAL || 5 * 60 * 1000; // Default: 5 minutes
    
    setInterval(async () => {
      try {
        if (this.pendingTransactions.length > 0) {
          logger.info(`Periodic mining triggered with ${this.pendingTransactions.length} pending transactions`);
          await this.mineNewBlock();
        }
      } catch (error) {
        logger.error(`Error in periodic mining: ${error.message}`);
      }
    }, interval);
    
    logger.info(`Periodic mining started, interval: ${interval}ms`);
  }

  getChainStats() {
    return {
      blocks: this.chain.length,
      transactions: this.chain.reduce((sum, block) => sum + block.data.length, 0),
      difficulty: this.difficulty,
      pendingTransactions: this.pendingTransactions.length,
      isValid: this.isChainValid(),
      lastBlockTime: this.chain.length > 0 ? this.getLatestBlock().timestamp : null
    };
  }
}

// Instanciate blockchain
const otrustChain = new Blockchain();
otrustChain.initialize().catch(error => {
  logger.error(`Failed to initialize blockchain: ${error.message}`);
  process.exit(1);
});

// Helper functions
function hashClaim(claimObj) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(claimObj))
    .digest('hex');
}

function verifySignature(publicKey, signature, data) {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, Buffer.from(signature, 'hex'));
  } catch (e) {
    logger.error(`Signature verification error: ${e.message}`);
    return false;
  }
}

async function findSemanticConflicts(newSemantic) {
  return await Claim.find({
    'semantic.subject': newSemantic.subject,
    'semantic.predicate': newSemantic.predicate,
    'semantic.object': { $ne: newSemantic.object }
  }).limit(10);
}

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { publicKey, signature, timestamp } = req.body;
    
    if (!publicKey || !signature || !timestamp) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Verify signature
    const payload = JSON.stringify({ action: 'register', publicKey, timestamp });
    if (!verifySignature(publicKey, signature, payload)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }
    
    // Check if user already exists
    let user = await User.findOne({ publicKey });
    if (user) {
      // Generate JWT token
      const token = jwt.sign(
        { publicKey },
        process.env.JWT_SECRET || 'your-default-secret-key',
        { expiresIn: process.env.JWT_EXPIRES || '30d' }
      );
      
      return res.status(200).json({
        message: 'User already registered',
        token,
        user: {
          publicKey: user.publicKey,
          displayName: user.displayName,
          score: user.score,
          role: user.role
        }
      });
    }
    
    // Create new user
    user = new User({
      publicKey,
      score: 1,
      created_at: Date.now()
    });
    
    await user.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { publicKey },
      process.env.JWT_SECRET || 'your-default-secret-key',
      { expiresIn: process.env.JWT_EXPIRES || '30d' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        publicKey: user.publicKey,
        displayName: user.displayName,
        score: user.score,
        role: user.role
      }
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { publicKey, signature, timestamp } = req.body;
    
    if (!publicKey || !signature || !timestamp) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Verify signature
    const payload = JSON.stringify({ action: 'login', publicKey, timestamp });
    if (!verifySignature(publicKey, signature, payload)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }
    
    // Check if user exists
    const user = await User.findOne({ publicKey });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update last activity
    await user.updateActivity();
    
    // Generate JWT token
    const token = jwt.sign(
      { publicKey },
      process.env.JWT_SECRET || 'your-default-secret-key',
      { expiresIn: process.env.JWT_EXPIRES || '30d' }
    );
    
    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        publicKey: user.publicKey,
        displayName: user.displayName,
        score: user.score,
        role: user.role
      }
    });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Token verification route
app.get('/api/auth/verify', auth, (req, res) => {
  res.status(200).json({
    user: {
      publicKey: req.user.publicKey,
      displayName: req.user.displayName,
      score: req.user.score,
      role: req.user.role
    }
  });
});

// User profile update
app.put('/api/user/profile', auth, async (req, res) => {
  try {
    const { displayName, email } = req.body;
    
    // Update fields
    if (displayName !== undefined) {
      req.user.displayName = displayName;
    }
    
    if (email !== undefined) {
      req.user.email = email;
    }
    
    await req.user.save();
    
    res.status(200).json({
      message: 'Profile updated',
      user: {
        publicKey: req.user.publicKey,
        displayName: req.user.displayName,
        score: req.user.score,
        role: req.user.role
      }
    });
  } catch (error) {
    logger.error(`Profile update error: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// API route to create a claim
app.post('/api/claim', auth, async (req, res) => {
  try {
    const input = req.body;

    if (!validateClaim(input)) {
      return res.status(400).json({ 
        error: 'Invalid input', 
        details: validateClaim.errors 
      });
    }

    const { claim, evidence, signature, publicKey, type, parent_id, timestamp, semantic } = input;
    const payload = JSON.stringify({ claim, evidence, publicKey, type, parent_id, timestamp, semantic });

    // Verify that the request is coming from the user who owns the publicKey
    if (publicKey !== req.user.publicKey) {
      return res.status(403).json({ error: 'Unauthorized: Public key mismatch' });
    }

    // Verify the signature
    if (!verifySignature(publicKey, signature, payload)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // Generate unique id
    const id = hashClaim({ claim, evidence, publicKey, signature, timestamp });
    
    // Check for duplicate
    const existingClaim = await Claim.findOne({ id });
    if (existingClaim) {
      return res.status(409).json({ error: 'Duplicate claim' });
    }

    // Create a new claim
    const claimObj = new Claim({
      id,
      claim,
      evidence,
      signature,
      publicKey,
      type,
      parent_id: parent_id || null,
      timestamp,
      semantic,
      proofChain: []
    });

    // Save the claim
    await claimObj.save();

    // Update user
    req.user.claims.push(claimObj._id);
    await req.user.save();

    // Create blockchain transaction (fingerprint)
    const blockchainTransaction = {
      id: id,
      type: 'claim',
      hash: hashClaim(claimObj),
      publicKey: publicKey,
      timestamp: timestamp,
      contentHash: crypto.createHash('sha256').update(claim).digest('hex')
    };

    // Add to blockchain
    await otrustChain.addTransaction(blockchainTransaction);
    
    // Update blockchain reference
    const txInChain = await otrustChain.getTransactionInChain(id);
    if (txInChain) {
      claimObj.blockchainRef = {
        transactionId: id,
        blockHash: txInChain.blockHash,
        blockIndex: txInChain.blockIndex,
        timestamp: txInChain.timestamp
      };
      await claimObj.save();
    }

    // Find semantic conflicts
    const conflicts = await findSemanticConflicts(semantic);

    // Return success with claim details
    res.status(201).json({ 
      message: 'Claim registered', 
      id: claimObj.id, 
      conflicts: conflicts.map(c => ({ id: c.id, claim: c.claim })),
      blockchainStatus: txInChain ? 'verified' : 'pending'
    });
  } catch (error) {
    logger.error(`Error creating claim: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// API route to add proof
app.post('/api/proof', auth, async (req, res) => {
  try {
    const input = req.body;

    if (!validateProof(input)) {
      return res.status(400).json({ 
        error: 'Invalid proof input', 
        details: validateProof.errors 
      });
    }

    const { claimId, action, signature, publicKey, timestamp, reason, confidence } = input;
    const payload = JSON.stringify({ claimId, action, publicKey, timestamp, reason, confidence });

    // Verify that the request is coming from the user who owns the publicKey
    if (publicKey !== req.user.publicKey) {
      return res.status(403).json({ error: 'Unauthorized: Public key mismatch' });
    }

    // Verify the signature
    if (!verifySignature(publicKey, signature, payload)) {
      return res.status(403).json({ error: 'Invalid proof signature' });
    }

    // Find the claim
    const targetClaim = await Claim.findOne({ id: claimId });
    if (!targetClaim) {
      return res.status(404).json({ error: 'Claim not found' });
    }

    // Check if the user has already provided proof for this claim
    const existingProof = targetClaim.proofChain.find(p => p.publicKey === publicKey);
    if (existingProof) {
      return res.status(409).json({ error: 'User has already provided proof for this claim' });
    }

    // Prevent self-verification
    if (targetClaim.publicKey === publicKey && action === 'confirmed') {
      return res.status(403).json({ error: 'Cannot verify your own claim' });
    }

    // Add proof
    const proof = {
      claimId,
      action,
      signature,
      publicKey,
      timestamp,
      reason: reason || '',
      confidence: confidence || 1.0
    };
    
    targetClaim.proofChain.push(proof);
    
    // Calculate credibility
    const credibility = await targetClaim.calculateCredibility();

    // Add proof-transaction to blockchain
    const proofTransaction = {
      id: hashClaim(proof),
      type: 'proof',
      claimId: claimId,
      action: action,
      publicKey: publicKey,
      timestamp: timestamp,
      hash: crypto.createHash('sha256').update(JSON.stringify(proof)).digest('hex')
    };

    await otrustChain.addTransaction(proofTransaction);

    // Update user statistics
    req.user.proofs.push({
      claimId,
      action,
      timestamp
    });

    // Update user reputation based on action
    if (action === 'confirmed') {
      req.user.verified += 1;
      req.user.score += 2;
    } else if (action === 'disputed') {
      req.user.disputed += 1;
      req.user.score += 1;
    } else if (action === 'invalidated') {
      req.user.score -= 3;
    }
    
    await req.user.save();

    res.status(201).json({ 
      message: 'Proof added', 
      claimId,
      credibility: credibility,
      blockchainStatus: 'pending'
    });
  } catch (error) {
    logger.error(`Error adding proof: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Get all claims with pagination and filtering
app.get('/api/claims', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;
    
    // Filtering options
    const filter = {};
    
    if (req.query.type) filter.type = req.query.type;
    if (req.query.publicKey) filter.publicKey = req.query.publicKey;
    
    // Semantic filters
    if (req.query.subject) filter['semantic.subject'] = req.query.subject;
    if (req.query.predicate) filter['semantic.predicate'] = req.query.predicate;
    if (req.query.object) filter['semantic.object'] = req.query.object;
    
    // Verification status filter
    if (req.query.verified === 'true') {
      filter.blockchainRef = { $exists: true };
      filter.$expr = { $gt: [{ $size: { $filter: { 
        input: "$proofChain", 
        as: "proof", 
        cond: { $eq: ["$$proof.action", "confirmed"] } 
      }}}, { $size: { $filter: { 
        input: "$proofChain", 
        as: "proof", 
        cond: { $eq: ["$$proof.action", "disputed"] } 
      }}}]};
    } else if (req.query.verified === 'false') {
      filter.$or = [
        { blockchainRef: { $exists: false } },
        { $expr: { $lte: [{ $size: { $filter: { 
          input: "$proofChain", 
          as: "proof", 
          cond: { $eq: ["$$proof.action", "confirmed"] } 
        }}}, { $size: { $filter: { 
          input: "$proofChain", 
          as: "proof", 
          cond: { $eq: ["$$proof.action", "disputed"] } 
        }}}]}}
      ];
    }
    
    // Text search
    if (req.query.search) {
      filter.$text = { $search: req.query.search };
    }
    
    // Date range filter
    if (req.query.fromDate) {
      filter.timestamp = { $gte: parseInt(req.query.fromDate) };
    }
    if (req.query.toDate) {
      if (filter.timestamp) {
        filter.timestamp.$lte = parseInt(req.query.toDate);
      } else {
        filter.timestamp = { $lte: parseInt(req.query.toDate) };
      }
    }
    
    // Sorting
    const sort = {};
    if (req.query.sort === 'credibility') {
      sort.credibilityScore = -1;
    } else if (req.query.sort === 'oldest') {
      sort.timestamp = 1;
    } else {
      sort.timestamp = -1; // Default: newest first
    }
    
    // Count total
    const total = await Claim.countDocuments(filter);
    
    // Get claims
    const claims = await Claim.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .select({
        id: 1,
        claim: 1,
        publicKey: 1,
        type: 1,
        timestamp: 1,
        semantic: 1,
        credibilityScore: 1,
        'blockchainRef.blockHash': 1,
        'proofChain.action': 1
      });
    
    // Calculate pagination info
    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrev = page > 1;
    
    res.json({
      claims,
      meta: {
        page,
        limit,
        total,
        totalPages,
        hasNext,
        hasPrev
      }
    });
  } catch (error) {
    logger.error(`Error fetching claims: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Get a specific claim
app.get('/api/claim/:id', async (req, res) => {
  try {
    const claim = await Claim.findOne({ id: req.params.id });
    if (!claim) {
      return res.status(404).json({ error: 'Not found' });
    }
    
    // Calculate credibility
    const credibility = await claim.calculateCredibility();
    
    // Get blockchain verification
    let blockchainVerification = null;
    if (claim.blockchainRef) {
      const block = await otrustChain.getBlockByHash(claim.blockchainRef.blockHash);
      if (block) {
        blockchainVerification = {
          blockHash: claim.blockchainRef.blockHash,
          blockIndex: claim.blockchainRef.blockIndex,
          timestamp: new Date(claim.blockchainRef.timestamp).toISOString(),
          verified: true
        };
      }
    }
    
    // Get related claims (same subject or parent/child)
    const relatedClaims = await Claim.find({
      $or: [
        { 'semantic.subject': claim.semantic.subject, id: { $ne: claim.id } },
        { parent_id: claim.id },
        { id: claim.parent_id }
      ]
    }).limit(5).select({
      id: 1,
      claim: 1,
      credibilityScore: 1,
      timestamp: 1
    });
    
    res.json({
      claim: claim.toObject(),
      credibility,
      blockchainVerification,
      relatedClaims
    });
  } catch (error) {
    logger.error(`Error fetching claim: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Verify a claim against blockchain
app.get('/api/claim/:id/verify', async (req, res) => {
  try {
    const claim = await Claim.findOne({ id: req.params.id });
    if (!claim) {
      return res.status(404).json({ error: 'Claim not found' });
    }
    
    const originalHash = hashClaim({
      claim: claim.claim,
      evidence: claim.evidence,
      publicKey: claim.publicKey,
      signature: claim.signature,
      timestamp: claim.timestamp
    });
    
    const blockchainTx = await otrustChain.getTransactionInChain(claim.id);
    
    if (blockchainTx) {
      // Verify that blockchain is intact
      const isChainValid = otrustChain.isChainValid();
      
      res.json({
        claim: claim.id,
        verified: true,
        blockHash: blockchainTx.blockHash,
        blockIndex: blockchainTx.blockIndex,
        timestamp: new Date(blockchainTx.timestamp).toISOString(),
        originalHash: originalHash,
        storedHash: blockchainTx.transaction.hash,
        hashMatch: originalHash === blockchainTx.transaction.hash,
        blockchainValid: isChainValid
      });
    } else {
      res.json({
        claim: claim.id,
        verified: false,
        message: 'Claim not found in blockchain'
      });
    }
  } catch (error) {
    logger.error(`Error verifying claim: ${error.message}`);
    res.status(500).json({ error: 'Verification error', message: error.message });
  }
});

// Claim versioning and updates
app.put('/api/claim/:id', auth, async (req, res) => {
  try {
    const claim = await Claim.findOne({ id: req.params.id });
    if (!claim) {
      return res.status(404).json({ error: 'Claim not found' });
    }
    
    // Verify ownership
    if (claim.publicKey !== req.user.publicKey) {
      return res.status(403).json({ error: 'Not authorized to update this claim' });
    }
    
    const { signature, updates } = req.body;
    if (!signature || !updates) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Verify signature
    const payload = JSON.stringify({ id: claim.id, updates, timestamp: Date.now() });
    if (!verifySignature(req.user.publicKey, signature, payload)) {
      return res.status(403).json({ error: 'Invalid signature' });
    }
    
    // Save history
    const historicalVersion = {...claim.toObject()};
    delete historicalVersion._id;
    delete historicalVersion.history;
    
    claim.history.push(historicalVersion);
    claim.version += 1;
    
    // Apply updates
    const allowedUpdates = ['evidence', 'claim'];
    for (const field of allowedUpdates) {
      if (updates[field]) {
        claim[field] = updates[field];
      }
    }
    
    // Allow updates to semantic fields but not the entire object
    if (updates.semantic) {
      const allowedSemanticUpdates = ['subject', 'predicate', 'object'];
      for (const field of allowedSemanticUpdates) {
        if (updates.semantic[field]) {
          claim.semantic[field] = updates.semantic[field];
        }
      }
    }
    
    await claim.save();
    
    // Add update transaction to blockchain
    const updateTransaction = {
      id: `${claim.id}_v${claim.version}`,
      type: 'claim_update',
      claimId: claim.id,
      version: claim.version,
      publicKey: req.user.publicKey,
      timestamp: Date.now(),
      hash: hashClaim(claim)
    };
    
    await otrustChain.addTransaction(updateTransaction);
    
    res.json({
      message: 'Claim updated',
      id: claim.id,
      version: claim.version
    });
  } catch (error) {
    logger.error(`Error updating claim: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Get claim history
app.get('/api/claim/:id/history', async (req, res) => {
  try {
    const claim = await Claim.findOne({ id: req.params.id });
    if (!claim) {
      return res.status(404).json({ error: 'Claim not found' });
    }
    
    const history = claim.history.map(version => ({
      version: version.version,
      timestamp: version.updatedAt || version.timestamp,
      claim: version.claim,
      evidence: version.evidence,
      semantic: version.semantic
    }));
    
    res.json({
      id: claim.id,
      currentVersion: claim.version,
      history
    });
  } catch (error) {
    logger.error(`Error fetching claim history: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Get user information
app.get('/api/user/:pubkey', async (req, res) => {
  try {
    const user = await User.findOne({ publicKey: req.params.pubkey });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get the user's recent claims
    const recentClaims = await Claim.find({ publicKey: req.params.pubkey })
      .sort({ timestamp: -1 })
      .limit(10)
      .select({
        id: 1,
        claim: 1,
        timestamp: 1,
        credibilityScore: 1,
        'blockchainRef.blockHash': 1
      });
    
    // Get stats on confirmations and disputes
    const stats = {
      claimsCount: await Claim.countDocuments({ publicKey: req.params.pubkey }),
      confirmedByOthers: await Claim.countDocuments({ 
        publicKey: req.params.pubkey,
        proofChain: { 
          $elemMatch: { 
            action: 'confirmed',
            publicKey: { $ne: req.params.pubkey }
          }
        }
      }),
      disputedByOthers: await Claim.countDocuments({ 
        publicKey: req.params.pubkey,
        proofChain: { 
          $elemMatch: { 
            action: 'disputed',
            publicKey: { $ne: req.params.pubkey }
          }
        }
      })
    };
    
    res.json({
      publicKey: req.params.pubkey,
      displayName: user.displayName,
      score: user.score,
      verified: user.verified,
      disputed: user.disputed,
      created_at: user.created_at,
      lastActive: user.lastActive,
      stats,
      recentClaims
    });
  } catch (error) {
    logger.error(`Error fetching user: ${error.message}`);
    res.status(500).json({ error: 'Server error', message: error.message });
  }
});

// Get blockchain statistics
app.get('/api/blockchain/stats', async (req, res) => {
  try {
    const stats = otrustChain.getChainStats();
    const latestBlock = otrustChain.getLatestBlock();
    
    res.json({
      blocks: stats.blocks,
      latestBlock: {
        index: latestBlock.index,
        hash: latestBlock.hash,
        transactions: latestBlock.data.length,
        timestamp: new Date(latestBlock.timestamp).toISOString()
      },
      pendingTransactions: stats.pendingTransactions,
      isValid: stats.isValid,
      difficulty: stats.difficulty,
      totalTransactions: stats.transactions
    });
  } catch (error) {
    logger.error(`Error fetching blockchain stats: ${error.message}`);
    res.status(500).json({ error: 'Blockchain stats error', message: error.message });
  }
});

// Get a specific block
app.get('/api/blockchain/block/:hash', async (req, res) => {
  try {
    const block = await otrustChain.getBlockByHash(req.params.hash);
    if (!block) {
      return res.status(404).json({ error: 'Block not found' });
    }
    
    res.json({
      index: block.index,
      timestamp: new Date(block.timestamp).toISOString(),
      hash: block.hash,
      previousHash: block.previousHash,
      nonce: block.nonce,
      merkleRoot: block.merkleRoot,
      transactions: block.data.length,
      transactionIds: block.data.map(tx => tx.id)
    });
  } catch (error) {
    logger.error(`Error fetching block: ${error.message}`);
    res.status(500).json({ error: 'Block fetch error', message: error.message });
  }
});

// Force a new block (admin only)
app.post('/api/blockchain/forceBlock', auth, adminOnly, async (req, res) => {
  try {
    const newBlock = await otrustChain.forceNewBlock();
    
    if (newBlock) {
      res.json({
        message: 'New block mined',
        block: {
          index: newBlock.index,
          hash: newBlock.hash,
          transactions: newBlock.data.length
        }
      });
    } else {
      res.json({
        message: 'No pending transactions to mine'
      });
    }
  } catch (error) {
    logger.error(`Error forcing block: ${error.message}`);
    res.status(500).json({ error: 'Blockchain error', message: error.message });
  }
});

// Search functionality
app.get('/api/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) {
      return res.status(400).json({ error: 'Search query required' });
    }
    
    // Limit to 50 results for performance
    const limit = parseInt(req.query.limit) || 50;
    
    // Perform text search
    const results = await Claim.find(
      { $text: { $search: query } },
      { score: { $meta: "textScore" } }
    )
    .sort({ score: { $meta: "textScore" } })
    .limit(limit)
    .select({
      id: 1,
      claim: 1,
      publicKey: 1,
      timestamp: 1,
      semantic: 1,
      credibilityScore: 1
    });
    
    // If text search doesn't yield results, try semantic search
    if (results.length === 0) {
      // Search in semantic fields
      const semanticResults = await Claim.find({
        $or: [
          { 'semantic.subject': { $regex: query, $options: 'i' } },
          { 'semantic.predicate': { $regex: query, $options: 'i' } },
          { 'semantic.object': { $regex: query, $options: 'i' } }
        ]
      })
      .sort({ credibilityScore: -1 })
      .limit(limit)
      .select({
        id: 1,
        claim: 1,
        publicKey: 1,
        timestamp: 1,
        semantic: 1,
        credibilityScore: 1
      });
      
      return res.json({
        results: semanticResults,
        count: semanticResults.length,
        searchType: 'semantic'
      });
    }
    
    res.json({
      results,
      count: results.length,
      searchType: 'text'
    });
  } catch (error) {
    logger.error(`Error during search: ${error.message}`);
    res.status(500).json({ error: 'Search error', message: error.message });
  }
});

// System statistics and analytics
app.get('/api/stats', async (req, res) => {
  try {
    const stats = {
      claims: await Claim.countDocuments(),
      users: await User.countDocuments(),
      blockchainVerifiedClaims: await Claim.countDocuments({ 'blockchainRef.blockHash': { $exists: true } }),
      proofs: await Claim.aggregate([
        { $unwind: "$proofChain" },
        { $group: { _id: null, count: { $sum: 1 } } }
      ]).then(result => result.length > 0 ? result[0].count : 0),
      conflicts: await Claim.aggregate([
        { 
          $group: {
            _id: { subject: "$semantic.subject", predicate: "$semantic.predicate" },
            objects: { $addToSet: "$semantic.object" },
            count: { $sum: 1 }
          }
        },
        { $match: { count: { $gt: 1 } } },
        { $count: "conflicts" }
      ]).then(result => result.length > 0 ? result[0].conflicts : 0)
    };
    
    // Get top claims by credibility
    const topClaims = await Claim.find()
      .sort({ credibilityScore: -1 })
      .limit(10)
      .select({
        id: 1,
        claim: 1,
        credibilityScore: 1,
        publicKey: 1
      });
    
    // Get top users by reputation
    const topUsers = await User.find()
      .sort({ score: -1 })
      .limit(10)
      .select({
        publicKey: 1,
        displayName: 1,
        score: 1
      });
    
    // Get blockchain stats
    const blockchainStats = otrustChain.getChainStats();
    
    // Get recent activity
    const recentActivity = await Claim.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select({
        id: 1,
        claim: 1,
        publicKey: 1,
        timestamp: 1,
        type: 1
      });
    
    res.json({
      stats,
      blockchain: {
        blocks: blockchainStats.blocks,
        transactions: blockchainStats.transactions,
        pendingTransactions: blockchainStats.pendingTransactions
      },
      topClaims,
      topUsers,
      recentActivity
    });
  } catch (error) {
    logger.error(`Error fetching stats: ${error.message}`);
    res.status(500).json({ error: 'Stats error', message: error.message });
  }
});

// Network synchronization with other OTRUST nodes
app.post('/api/sync', auth, adminOnly, async (req, res) => {
  try {
    const { claims, users, nodeId, signature } = req.body;
    
    if (!nodeId || !signature || !claims) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Verify the signature (implementation depends on your trust model for nodes)
    // This is a simplified example
    const payload = JSON.stringify({ nodeId, claimsCount: claims.length });
    const trustedNodes = process.env.TRUSTED_NODES ? JSON.parse(process.env.TRUSTED_NODES) : {};
    
    if (!trustedNodes[nodeId]) {
      return res.status(403).json({ error: 'Node not trusted' });
    }
    
    if (!verifySignature(trustedNodes[nodeId], signature, payload)) {
      return res.status(403).json({ error: 'Invalid node signature' });
    }
    
    // Process claims
    let processed = 0;
    let skipped = 0;
    
    for (const claim of claims) {
      // Check if claim already exists
      const existingClaim = await Claim.findOne({ id: claim.id });
      if (existingClaim) {
        // Maybe update with new proofs?
        skipped++;
        continue;
      }
      
      // Create new claim
      const newClaim = new Claim(claim);
      await newClaim.save();
      processed++;
      
      // Add to blockchain if not already there
      const txInChain = await otrustChain.getTransactionInChain(claim.id);
      if (!txInChain) {
        const blockchainTransaction = {
          id: claim.id,
          type: 'claim',
          hash: hashClaim(claim),
          publicKey: claim.publicKey,
          timestamp: claim.timestamp,
          contentHash: crypto.createHash('sha256').update(claim.claim).digest('hex'),
          source: nodeId
        };
        
        await otrustChain.addTransaction(blockchainTransaction);
      }
    }
    
    // Process users if provided
    let usersProcessed = 0;
    if (users && Array.isArray(users)) {
      for (const user of users) {
        // Update user data if exists, otherwise create
        await User.findOneAndUpdate(
          { publicKey: user.publicKey },
          { $set: user },
          { upsert: true, new: true }
        );
        usersProcessed++;
      }
    }
    
    res.json({
      message: 'Sync processed',
      processed,
      skipped,
      usersProcessed
    });
  } catch (error) {
    logger.error(`Error during sync: ${error.message}`);
    res.status(500).json({ error: 'Sync error', message: error.message });
  }
});

// System maintenance (admin only)
app.post('/api/system/maintenance', auth, adminOnly, async (req, res) => {
  try {
    const { action } = req.body;
    
    switch (action) {
      case 'recalculateCredibility':
        // Recalculate credibility scores for all claims
        const claims = await Claim.find();
        let processed = 0;
        
        for (const claim of claims) {
          await claim.calculateCredibility();
          processed++;
        }
        
        res.json({
          message: 'Credibility recalculated',
          processed
        });
        break;
        
      case 'cleanupOrphans':
        // Remove orphaned proofs (references to non-existent claims)
        const users = await User.find();
        let orphansRemoved = 0;
        
        for (const user of users) {
          const validProofs = [];
          
          for (const proof of user.proofs) {
            const claimExists = await Claim.exists({ id: proof.claimId });
            if (claimExists) {
              validProofs.push(proof);
            } else {
              orphansRemoved++;
            }
          }
          
          user.proofs = validProofs;
          await user.save();
        }
        
        res.json({
          message: 'Orphaned proofs cleaned up',
          orphansRemoved
        });
        break;
        
      case 'validateBlockchain':
        // Validate blockchain integrity
        const isValid = otrustChain.isChainValid();
        
        res.json({
          message: 'Blockchain validation complete',
          isValid
        });
        break;
        
      default:
        res.status(400).json({ error: 'Unknown maintenance action' });
    }
  } catch (error) {
    logger.error(`Error during maintenance: ${error.message}`);
    res.status(500).json({ error: 'Maintenance error', message: error.message });
  }
});

// Export blockchain data (admin only)
app.get('/api/system/export', auth, adminOnly, async (req, res) => {
  try {
    const { type } = req.query;
    
    switch (type) {
      case 'blockchain':
        // Export blockchain data
        res.json({
          blocks: otrustChain.chain,
          pendingTransactions: otrustChain.pendingTransactions
        });
        break;
        
      case 'claims':
        // Export all claims
        const claims = await Claim.find().limit(1000);
        res.json({ claims });
        break;
        
      case 'users':
        // Export users (without sensitive data)
        const users = await User.find().select({
          publicKey: 1,
          displayName: 1,
          score: 1,
          verified: 1,
          disputed: 1,
          created_at: 1
        });
        
        res.json({ users });
        break;
        
      default:
        res.status(400).json({ error: 'Unknown export type' });
    }
  } catch (error) {
    logger.error(`Error during export: ${error.message}`);
    res.status(500).json({ error: 'Export error', message: error.message });
  }
});

// Semantic query endpoint
app.get('/api/semantic/:subject/:predicate', async (req, res) => {
  try {
    const { subject, predicate } = req.params;
    
    // Find all claims with the given subject and predicate
    const claims = await Claim.find({
      'semantic.subject': subject,
      'semantic.predicate': predicate
    })
    .sort({ credibilityScore: -1 })
    .limit(10);
    
    if (claims.length === 0) {
      return res.status(404).json({ 
        message: 'No claims found with the given subject and predicate',
        subject,
        predicate
      });
    }
    
    // Gather all possible objects for this subject-predicate pair
    const objects = claims.map(claim => ({
      object: claim.semantic.object,
      credibility: claim.credibilityScore,
      claimId: claim.id,
      confirmations: claim.proofChain.filter(p => p.action === 'confirmed').length,
      disputes: claim.proofChain.filter(p => p.action === 'disputed').length
    }));
    
    // Check if there's a consensus or conflicting claims
    const uniqueObjects = [...new Set(claims.map(c => c.semantic.object))];
    const hasConsensus = uniqueObjects.length === 1;
    
    res.json({
      subject,
      predicate,
      objects,
      hasConsensus,
      consensusValue: hasConsensus ? uniqueObjects[0] : null,
      claimsCount: claims.length
    });
  } catch (error) {
    logger.error(`Error in semantic query: ${error.message}`);
    res.status(500).json({ error: 'Query error', message: error.message });
  }
});

// Advanced semantic queries
app.post('/api/semantic/query', async (req, res) => {
  try {
    const { query } = req.body;
    
    if (!query || typeof query !== 'object') {
      return res.status(400).json({ error: 'Invalid query format' });
    }
    
    // Build MongoDB query from semantic query
    const mongoQuery = {};
    
    if (query.subject) {
      mongoQuery['semantic.subject'] = query.subject;
    }
    
    if (query.predicate) {
      mongoQuery['semantic.predicate'] = query.predicate;
    }
    
    if (query.object) {
      mongoQuery['semantic.object'] = query.object;
    }
    
    // Additional filters
    if (query.minCredibility) {
      mongoQuery.credibilityScore = { $gte: parseFloat(query.minCredibility) };
    }
    
    if (query.verifiedOnly === true) {
      mongoQuery.blockchainRef = { $exists: true };
    }
    
    // Execute query
    const claims = await Claim.find(mongoQuery)
      .sort({ credibilityScore: -1 })
      .limit(query.limit || 50);
    
    // Transform results based on what was requested
    if (query.format === 'graph') {
      // Return as knowledge graph format
      const nodes = new Set();
      const edges = [];
      
      claims.forEach(claim => {
        nodes.add(claim.semantic.subject);
        nodes.add(claim.semantic.object);
        
        edges.push({
          source: claim.semantic.subject,
          predicate: claim.semantic.predicate,
          target: claim.semantic.object,
          weight: claim.credibilityScore,
          id: claim.id
        });
      });
      
      res.json({
        nodes: Array.from(nodes).map(node => ({ id: node })),
        edges
      });
    } else {
      // Return regular results
      res.json({
        claims: claims.map(claim => ({
          id: claim.id,
          subject: claim.semantic.subject,
          predicate: claim.semantic.predicate,
          object: claim.semantic.object,
          credibility: claim.credibilityScore,
          timestamp: claim.timestamp
        })),
        count: claims.length
      });
    }
  } catch (error) {
    logger.error(`Error in advanced semantic query: ${error.message}`);
    res.status(500).json({ error: 'Query error', message: error.message });
  }
});

// API Documentation
app.get('/api', (req, res) => {
  res.json({
    version: '1.0.0',
    endpoints: {
      claims: {
        'GET /api/claims': 'Get all claims with pagination and filtering',
        'GET /api/claim/:id': 'Get a specific claim by ID',
        'POST /api/claim': 'Create a new claim',
        'PUT /api/claim/:id': 'Update an existing claim',
        'GET /api/claim/:id/verify': 'Verify a claim against the blockchain',
        'GET /api/claim/:id/history': 'Get the history of a claim'
      },
      proofs: {
        'POST /api/proof': 'Add a proof to a claim'
      },
      users: {
        'GET /api/user/:pubkey': 'Get information about a user',
        'PUT /api/user/profile': 'Update user profile'
      },
      auth: {
        'POST /api/auth/register': 'Register a new user',
        'POST /api/auth/login': 'Log in',
        'GET /api/auth/verify': 'Verify authentication token'
      },
      blockchain: {
        'GET /api/blockchain/stats': 'Get blockchain statistics',
        'GET /api/blockchain/block/:hash': 'Get a specific block',
        'POST /api/blockchain/forceBlock': 'Force a new block (admin only)'
      },
      semantic: {
        'GET /api/semantic/:subject/:predicate': 'Get semantic claims',
        'POST /api/semantic/query': 'Advanced semantic queries'
      },
      search: {
        'GET /api/search': 'Search claims'
      },
      stats: {
        'GET /api/stats': 'Get system statistics'
      },
      system: {
        'POST /api/system/maintenance': 'System maintenance (admin only)',
        'GET /api/system/export': 'Export system data (admin only)'
      },
      sync: {
        'POST /api/sync': 'Synchronize with other OTRUST nodes (admin only)'
      }
    },
    documentation: 'https://docs.otrust.io'
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  
  res.json({ 
    status: 'ok', 
    version: '1.0.0',
    db: dbStatus,
    blockchain: {
      blocks: otrustChain.chain.length,
      isValid: otrustChain.isChainValid()
    },
    uptime: Math.floor(process.uptime()),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  logger.error(err.stack);
  
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred' : err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', message: 'The requested resource was not found' });
});

// Connection and startup
async function startServer() {
  try {
    // Connect to MongoDB
    await connectDB();
    
    // Wait until blockchain is initialized
    while (!otrustChain.initialized) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    // Start server
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      logger.info(`OTRUST server with lightweight blockchain running on port ${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`MongoDB connected: ${mongoose.connection.host}`);
      logger.info(`Blockchain initialized with ${otrustChain.chain.length} blocks`);
    });
    
    // Set up graceful shutdown
    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
}

// Graceful shutdown handler
async function gracefulShutdown() {
  logger.info('Shutting down gracefully...');
  
  try {
    // Mine any remaining transactions
    if (otrustChain.pendingTransactions.length > 0) {
      logger.info(`Mining ${otrustChain.pendingTransactions.length} pending transactions before shutdown`);
      await otrustChain.forceNewBlock();
    }
    
    // Close database connections
    logger.info('Closing MongoDB connection');
    await mongoose.connection.close();
    
    logger.info('Closing LevelDB connection');
    await blockchainDB.close();
    
    logger.info('Shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error(`Error during shutdown: ${error.message}`);
    process.exit(1);
  }
}

// Start the server
startServer();

module.exports = app; // For testing
