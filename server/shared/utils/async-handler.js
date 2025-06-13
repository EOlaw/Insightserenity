// server/shared/utils/async-handler.js
/**
 * @file Async Handler Utility
 * @description Wrapper for handling async route handlers and avoiding try-catch blocks
 * @version 3.0.0
 */

/**
 * Wrap async route handlers to catch errors
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Express middleware function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Wrap async route handlers with additional error context
 * @param {Function} fn - Async function to wrap
 * @param {string} context - Error context for logging
 * @returns {Function} Express middleware function
 */
const asyncHandlerWithContext = (fn, context) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(error => {
      // Add context to error
      error.context = context;
      error.requestId = req.id;
      next(error);
    });
  };
};

/**
 * Execute multiple async middleware in sequence
 * @param {Array<Function>} middlewares - Array of middleware functions
 * @returns {Function} Express middleware function
 */
const asyncMiddlewareChain = (middlewares) => {
  return async (req, res, next) => {
    try {
      for (const middleware of middlewares) {
        await new Promise((resolve, reject) => {
          middleware(req, res, (error) => {
            if (error) reject(error);
            else resolve();
          });
        });
      }
      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Retry async operations with exponential backoff
 * @param {Function} fn - Async function to retry
 * @param {Object} options - Retry options
 * @returns {Promise} Result of the function
 */
const retryAsync = async (fn, options = {}) => {
  const {
    maxAttempts = 3,
    initialDelay = 1000,
    maxDelay = 10000,
    factor = 2,
    onRetry = null
  } = options;
  
  let lastError;
  let delay = initialDelay;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      
      if (attempt === maxAttempts) {
        throw error;
      }
      
      if (onRetry) {
        onRetry(error, attempt);
      }
      
      // Wait before next attempt
      await new Promise(resolve => setTimeout(resolve, delay));
      
      // Calculate next delay with exponential backoff
      delay = Math.min(delay * factor, maxDelay);
    }
  }
  
  throw lastError;
};

/**
 * Execute async function with timeout
 * @param {Function} fn - Async function to execute
 * @param {number} timeout - Timeout in milliseconds
 * @param {string} timeoutMessage - Custom timeout message
 * @returns {Promise} Result of the function
 */
const withTimeout = async (fn, timeout, timeoutMessage = 'Operation timed out') => {
  return Promise.race([
    fn(),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error(timeoutMessage)), timeout)
    )
  ]);
};

/**
 * Execute multiple async operations in parallel with error handling
 * @param {Array<Function>} operations - Array of async functions
 * @param {Object} options - Execution options
 * @returns {Promise<Array>} Results array
 */
const parallelAsync = async (operations, options = {}) => {
  const {
    continueOnError = false,
    maxConcurrency = Infinity
  } = options;
  
  if (maxConcurrency === Infinity) {
    if (continueOnError) {
      const results = await Promise.allSettled(operations.map(op => op()));
      return results.map(result => 
        result.status === 'fulfilled' ? result.value : { error: result.reason }
      );
    }
    return Promise.all(operations.map(op => op()));
  }
  
  // Limited concurrency
  const results = [];
  const executing = [];
  
  for (const operation of operations) {
    const promise = Promise.resolve().then(() => operation());
    results.push(promise);
    
    if (operations.length >= maxConcurrency) {
      executing.push(promise);
      
      if (executing.length >= maxConcurrency) {
        await Promise.race(executing);
        executing.splice(executing.findIndex(p => p === promise), 1);
      }
    }
  }
  
  if (continueOnError) {
    const settled = await Promise.allSettled(results);
    return settled.map(result => 
      result.status === 'fulfilled' ? result.value : { error: result.reason }
    );
  }
  
  return Promise.all(results);
};

/**
 * Create a debounced async function
 * @param {Function} fn - Async function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Debounced function
 */
const debounceAsync = (fn, delay) => {
  let timeoutId;
  let pending;
  
  return function(...args) {
    clearTimeout(timeoutId);
    
    if (!pending) {
      pending = new Promise((resolve, reject) => {
        timeoutId = setTimeout(async () => {
          try {
            const result = await fn.apply(this, args);
            resolve(result);
          } catch (error) {
            reject(error);
          } finally {
            pending = null;
          }
        }, delay);
      });
    }
    
    return pending;
  };
};

/**
 * Create a throttled async function
 * @param {Function} fn - Async function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
const throttleAsync = (fn, limit) => {
  let inThrottle;
  let lastResult;
  
  return async function(...args) {
    if (!inThrottle) {
      inThrottle = true;
      
      try {
        lastResult = await fn.apply(this, args);
        return lastResult;
      } finally {
        setTimeout(() => {
          inThrottle = false;
        }, limit);
      }
    }
    
    return lastResult;
  };
};

/**
 * Memoize async function results
 * @param {Function} fn - Async function to memoize
 * @param {Function} keyGenerator - Function to generate cache key
 * @param {number} ttl - Time to live in milliseconds
 * @returns {Function} Memoized function
 */
const memoizeAsync = (fn, keyGenerator = (...args) => JSON.stringify(args), ttl = null) => {
  const cache = new Map();
  
  return async function(...args) {
    const key = keyGenerator(...args);
    
    // Check cache
    if (cache.has(key)) {
      const cached = cache.get(key);
      if (!ttl || Date.now() - cached.timestamp < ttl) {
        return cached.value;
      }
    }
    
    // Execute function
    const result = await fn.apply(this, args);
    
    // Store in cache
    cache.set(key, {
      value: result,
      timestamp: Date.now()
    });
    
    return result;
  };
};

/**
 * Create a circuit breaker for async operations
 * @param {Function} fn - Async function to protect
 * @param {Object} options - Circuit breaker options
 * @returns {Function} Protected function
 */
const circuitBreaker = (fn, options = {}) => {
  const {
    threshold = 5,
    timeout = 60000,
    resetTimeout = 30000
  } = options;
  
  let failures = 0;
  let lastFailureTime = null;
  let state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  
  return async function(...args) {
    // Check if circuit should be reset
    if (state === 'OPEN' && Date.now() - lastFailureTime > resetTimeout) {
      state = 'HALF_OPEN';
      failures = 0;
    }
    
    // If circuit is open, fail fast
    if (state === 'OPEN') {
      throw new Error('Circuit breaker is OPEN');
    }
    
    try {
      const result = await withTimeout(
        () => fn.apply(this, args),
        timeout,
        'Circuit breaker timeout'
      );
      
      // Reset on success
      if (state === 'HALF_OPEN') {
        state = 'CLOSED';
      }
      failures = 0;
      
      return result;
    } catch (error) {
      failures++;
      lastFailureTime = Date.now();
      
      if (failures >= threshold) {
        state = 'OPEN';
      }
      
      throw error;
    }
  };
};

/**
 * Batch async operations
 * @param {Function} fn - Async function that accepts array of items
 * @param {Object} options - Batching options
 * @returns {Function} Batched function
 */
const batchAsync = (fn, options = {}) => {
  const {
    maxBatchSize = 100,
    maxWaitTime = 10
  } = options;
  
  let batch = [];
  let batchPromise = null;
  let batchTimeout = null;
  
  const executeBatch = async () => {
    const currentBatch = batch;
    batch = [];
    batchPromise = null;
    
    if (batchTimeout) {
      clearTimeout(batchTimeout);
      batchTimeout = null;
    }
    
    try {
      const results = await fn(currentBatch.map(item => item.input));
      currentBatch.forEach((item, index) => {
        item.resolve(results[index]);
      });
    } catch (error) {
      currentBatch.forEach(item => {
        item.reject(error);
      });
    }
  };
  
  return function(input) {
    return new Promise((resolve, reject) => {
      batch.push({ input, resolve, reject });
      
      if (batch.length >= maxBatchSize) {
        executeBatch();
      } else if (!batchTimeout) {
        batchTimeout = setTimeout(executeBatch, maxWaitTime);
      }
    });
  };
};

module.exports = {
  asyncHandler,
  asyncHandlerWithContext,
  asyncMiddlewareChain,
  retryAsync,
  withTimeout,
  parallelAsync,
  debounceAsync,
  throttleAsync,
  memoizeAsync,
  circuitBreaker,
  batchAsync
};