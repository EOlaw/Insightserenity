// /server/shared/services/search-service.js

/**
 * @file Search Service
 * @description Elasticsearch integration for full-text search
 * @version 1.0.0
 */

const { Client } = require('@elastic/elasticsearch');

const config = require('../config');
const { AppError } = require('../utils/app-error');
const cacheHelper = require('../utils/helpers/cache-helper');
const logger = require('../utils/logger');

/**
 * Search Service Class
 */
class SearchService {
  constructor() {
    this.client = null;
    this.indices = {
      users: 'insightserenity_users',
      organizations: 'insightserenity_organizations',
      projects: 'insightserenity_projects',
      jobs: 'insightserenity_jobs',
      candidates: 'insightserenity_candidates',
      content: 'insightserenity_content',
      logs: 'insightserenity_logs'
    };
    
    this.initializeClient();
  }
  
  /**
   * Initialize Elasticsearch client
   */
  initializeClient() {
    try {
      this.client = new Client({
        node: config.elasticsearch.node || 'http://localhost:9200',
        auth: config.elasticsearch.auth ? {
          username: config.elasticsearch.auth.username,
          password: config.elasticsearch.auth.password
        } : undefined,
        ssl: config.elasticsearch.ssl || undefined,
        maxRetries: 3,
        requestTimeout: 30000,
        sniffOnStart: true,
        sniffInterval: 60000,
        sniffOnConnectionFault: true
      });
      
      // Test connection
      this.client.ping()
        .then(() => logger.info('Elasticsearch connected successfully'))
        .catch(err => logger.error('Elasticsearch connection failed:', err));
        
    } catch (error) {
      logger.error('Failed to initialize search service:', error);
    }
  }
  
  /**
   * Create index with mappings
   */
  async createIndex(indexName, mappings) {
    try {
      const exists = await this.client.indices.exists({ index: indexName });
      
      if (exists) {
        logger.info(`Index ${indexName} already exists`);
        return;
      }
      
      await this.client.indices.create({
        index: indexName,
        body: {
          settings: {
            number_of_shards: 1,
            number_of_replicas: 1,
            analysis: {
              analyzer: {
                autocomplete: {
                  tokenizer: 'autocomplete',
                  filter: ['lowercase']
                },
                autocomplete_search: {
                  tokenizer: 'lowercase'
                }
              },
              tokenizer: {
                autocomplete: {
                  type: 'edge_ngram',
                  min_gram: 2,
                  max_gram: 10,
                  token_chars: ['letter', 'digit']
                }
              }
            }
          },
          mappings
        }
      });
      
      logger.info(`Index ${indexName} created successfully`);
    } catch (error) {
      logger.error(`Failed to create index ${indexName}:`, error);
      throw new AppError('Failed to create search index', 500);
    }
  }
  
  /**
   * Initialize all indices
   */
  async initializeIndices() {
    // User index
    await this.createIndex(this.indices.users, {
      properties: {
        id: { type: 'keyword' },
        email: { 
          type: 'text',
          fields: {
            keyword: { type: 'keyword' }
          }
        },
        firstName: {
          type: 'text',
          analyzer: 'autocomplete',
          search_analyzer: 'autocomplete_search'
        },
        lastName: {
          type: 'text',
          analyzer: 'autocomplete',
          search_analyzer: 'autocomplete_search'
        },
        fullName: {
          type: 'text',
          analyzer: 'standard'
        },
        username: { type: 'keyword' },
        bio: { type: 'text' },
        skills: { type: 'keyword' },
        roles: { type: 'keyword' },
        organizations: {
          type: 'nested',
          properties: {
            id: { type: 'keyword' },
            name: { type: 'text' },
            role: { type: 'keyword' }
          }
        },
        active: { type: 'boolean' },
        createdAt: { type: 'date' },
        updatedAt: { type: 'date' }
      }
    });
    
    // Organization index
    await this.createIndex(this.indices.organizations, {
      properties: {
        id: { type: 'keyword' },
        name: {
          type: 'text',
          analyzer: 'autocomplete',
          search_analyzer: 'autocomplete_search',
          fields: {
            keyword: { type: 'keyword' }
          }
        },
        slug: { type: 'keyword' },
        description: { type: 'text' },
        type: { type: 'keyword' },
        industry: { type: 'keyword' },
        size: { type: 'keyword' },
        website: { type: 'keyword' },
        tags: { type: 'keyword' },
        location: {
          properties: {
            city: { type: 'text' },
            state: { type: 'text' },
            country: { type: 'keyword' },
            coordinates: { type: 'geo_point' }
          }
        },
        status: { type: 'keyword' },
        createdAt: { type: 'date' },
        updatedAt: { type: 'date' }
      }
    });
    
    // Jobs index
    await this.createIndex(this.indices.jobs, {
      properties: {
        id: { type: 'keyword' },
        title: {
          type: 'text',
          analyzer: 'standard',
          fields: {
            keyword: { type: 'keyword' }
          }
        },
        description: { type: 'text' },
        requirements: { type: 'text' },
        responsibilities: { type: 'text' },
        organizationId: { type: 'keyword' },
        organizationName: { type: 'text' },
        location: {
          properties: {
            type: { type: 'keyword' },
            city: { type: 'text' },
            state: { type: 'text' },
            country: { type: 'keyword' },
            coordinates: { type: 'geo_point' }
          }
        },
        salary: {
          properties: {
            min: { type: 'integer' },
            max: { type: 'integer' },
            currency: { type: 'keyword' },
            period: { type: 'keyword' }
          }
        },
        type: { type: 'keyword' },
        category: { type: 'keyword' },
        tags: { type: 'keyword' },
        skills: { type: 'keyword' },
        experience: { type: 'keyword' },
        education: { type: 'keyword' },
        status: { type: 'keyword' },
        postedDate: { type: 'date' },
        applicationDeadline: { type: 'date' },
        viewCount: { type: 'integer' },
        applicationCount: { type: 'integer' }
      }
    });
  }
  
  /**
   * Index document
   */
  async index(indexName, document, id = null) {
    try {
      const body = {
        index: indexName,
        body: document,
        refresh: 'wait_for'
      };
      
      if (id) {
        body.id = id;
      }
      
      const result = await this.client.index(body);
      
      logger.debug(`Document indexed in ${indexName}`, { id: result._id });
      
      return result;
    } catch (error) {
      logger.error(`Failed to index document in ${indexName}:`, error);
      throw new AppError('Failed to index document', 500);
    }
  }
  
  /**
   * Bulk index documents
   */
  async bulkIndex(indexName, documents) {
    try {
      const body = documents.flatMap(doc => [
        { index: { _index: indexName, _id: doc.id } },
        doc
      ]);
      
      const result = await this.client.bulk({ 
        body,
        refresh: 'wait_for'
      });
      
      if (result.errors) {
        logger.error('Bulk indexing had errors:', result.items);
      }
      
      logger.info(`Bulk indexed ${documents.length} documents in ${indexName}`);
      
      return result;
    } catch (error) {
      logger.error(`Failed to bulk index in ${indexName}:`, error);
      throw new AppError('Failed to bulk index documents', 500);
    }
  }
  
  /**
   * Search documents
   */
  async search(indexName, query, options = {}) {
    try {
      const {
        from = 0,
        size = 20,
        sort,
        filters = {},
        aggregations,
        highlight,
        source,
        suggest
      } = options;
      
      // Build query
      const body = {
        query: this.buildQuery(query, filters),
        from,
        size
      };
      
      // Add sorting
      if (sort) {
        body.sort = this.buildSort(sort);
      }
      
      // Add aggregations
      if (aggregations) {
        body.aggs = aggregations;
      }
      
      // Add highlighting
      if (highlight) {
        body.highlight = this.buildHighlight(highlight);
      }
      
      // Add source filtering
      if (source) {
        body._source = source;
      }
      
      // Add suggestions
      if (suggest) {
        body.suggest = this.buildSuggest(suggest);
      }
      
      // Check cache
      const cacheKey = `search:${indexName}:${JSON.stringify({ query, options })}`;
      const cached = await cacheHelper.get(cacheKey);
      if (cached) {
        return cached;
      }
      
      // Execute search
      const result = await this.client.search({
        index: indexName,
        body
      });
      
      // Format response
      const response = {
        total: result.hits.total.value,
        hits: result.hits.hits.map(hit => ({
          id: hit._id,
          score: hit._score,
          ...hit._source,
          highlight: hit.highlight
        })),
        aggregations: result.aggregations,
        suggestions: result.suggest
      };
      
      // Cache result
      await cacheHelper.set(cacheKey, response, 300); // 5 minutes
      
      return response;
    } catch (error) {
      logger.error(`Search failed in ${indexName}:`, error);
      throw new AppError('Search failed', 500);
    }
  }
  
  /**
   * Multi-index search
   */
  async multiSearch(indices, query, options = {}) {
    try {
      const searches = indices.map(index => ({
        index,
        ...options
      }));
      
      const body = searches.flatMap(search => [
        { index: search.index },
        {
          query: this.buildQuery(query, search.filters),
          size: search.size || 10,
          _source: search.source
        }
      ]);
      
      const result = await this.client.msearch({ body });
      
      return result.responses.map((response, index) => ({
        index: indices[index],
        total: response.hits.total.value,
        hits: response.hits.hits.map(hit => ({
          id: hit._id,
          score: hit._score,
          ...hit._source
        }))
      }));
    } catch (error) {
      logger.error('Multi-search failed:', error);
      throw new AppError('Multi-search failed', 500);
    }
  }
  
  /**
   * Autocomplete search
   */
  async autocomplete(indexName, field, query, options = {}) {
    const { size = 10, filters = {} } = options;
    
    const body = {
      query: {
        bool: {
          must: {
            match: {
              [field]: {
                query,
                analyzer: 'autocomplete_search'
              }
            }
          },
          filter: this.buildFilters(filters)
        }
      },
      size,
      _source: [field]
    };
    
    const result = await this.client.search({
      index: indexName,
      body
    });
    
    return result.hits.hits.map(hit => hit._source[field]);
  }
  
  /**
   * Update document
   */
  async update(indexName, id, updates) {
    try {
      const result = await this.client.update({
        index: indexName,
        id,
        body: {
          doc: updates,
          doc_as_upsert: true
        },
        refresh: 'wait_for'
      });
      
      logger.debug(`Document updated in ${indexName}`, { id });
      
      return result;
    } catch (error) {
      logger.error(`Failed to update document in ${indexName}:`, error);
      throw new AppError('Failed to update document', 500);
    }
  }
  
  /**
   * Delete document
   */
  async delete(indexName, id) {
    try {
      const result = await this.client.delete({
        index: indexName,
        id,
        refresh: 'wait_for'
      });
      
      logger.debug(`Document deleted from ${indexName}`, { id });
      
      return result;
    } catch (error) {
      if (error.statusCode === 404) {
        return { found: false };
      }
      
      logger.error(`Failed to delete document from ${indexName}:`, error);
      throw new AppError('Failed to delete document', 500);
    }
  }
  
  /**
   * Build search query
   */
  buildQuery(query, filters = {}) {
    if (!query || query === '*') {
      return {
        bool: {
          must: { match_all: {} },
          filter: this.buildFilters(filters)
        }
      };
    }
    
    return {
      bool: {
        must: {
          multi_match: {
            query,
            fields: ['*'],
            type: 'best_fields',
            fuzziness: 'AUTO'
          }
        },
        filter: this.buildFilters(filters)
      }
    };
  }
  
  /**
   * Build filters
   */
  buildFilters(filters) {
    const filterClauses = [];
    
    for (const [field, value] of Object.entries(filters)) {
      if (value === null || value === undefined) continue;
      
      if (Array.isArray(value)) {
        filterClauses.push({
          terms: { [field]: value }
        });
      } else if (typeof value === 'object') {
        // Range filter
        if (value.gte || value.lte || value.gt || value.lt) {
          filterClauses.push({
            range: { [field]: value }
          });
        }
        // Geo distance filter
        else if (value.distance && value.location) {
          filterClauses.push({
            geo_distance: {
              distance: value.distance,
              [field]: value.location
            }
          });
        }
      } else {
        filterClauses.push({
          term: { [field]: value }
        });
      }
    }
    
    return filterClauses;
  }
  
  /**
   * Build sort
   */
  buildSort(sort) {
    if (typeof sort === 'string') {
      const [field, order] = sort.split(':');
      return [{ [field]: { order: order || 'asc' } }];
    }
    
    if (Array.isArray(sort)) {
      return sort.map(s => {
        if (typeof s === 'string') {
          const [field, order] = s.split(':');
          return { [field]: { order: order || 'asc' } };
        }
        return s;
      });
    }
    
    return [sort];
  }
  
  /**
   * Build highlight
   */
  buildHighlight(fields) {
    if (fields === true) {
      return {
        fields: { '*': {} },
        pre_tags: ['<mark>'],
        post_tags: ['</mark>']
      };
    }
    
    const highlightFields = {};
    const fieldList = Array.isArray(fields) ? fields : [fields];
    
    fieldList.forEach(field => {
      highlightFields[field] = {};
    });
    
    return {
      fields: highlightFields,
      pre_tags: ['<mark>'],
      post_tags: ['</mark>']
    };
  }
  
  /**
   * Build suggest
   */
  buildSuggest(suggest) {
    return {
      text: suggest.text,
      completion: {
        field: suggest.field,
        size: suggest.size || 5,
        skip_duplicates: true,
        fuzzy: {
          fuzziness: 'AUTO'
        }
      }
    };
  }
  
  /**
   * Reindex data
   */
  async reindex(sourceIndex, destIndex) {
    try {
      const result = await this.client.reindex({
        body: {
          source: { index: sourceIndex },
          dest: { index: destIndex }
        },
        refresh: true
      });
      
      logger.info(`Reindexed from ${sourceIndex} to ${destIndex}`, {
        took: result.took,
        total: result.total
      });
      
      return result;
    } catch (error) {
      logger.error('Reindex failed:', error);
      throw new AppError('Reindex failed', 500);
    }
  }
  
  /**
   * Get index stats
   */
  async getIndexStats(indexName) {
    try {
      const stats = await this.client.indices.stats({ index: indexName });
      
      return {
        documentCount: stats._all.primaries.docs.count,
        sizeInBytes: stats._all.primaries.store.size_in_bytes,
        indexing: stats._all.primaries.indexing,
        search: stats._all.primaries.search
      };
    } catch (error) {
      logger.error(`Failed to get stats for ${indexName}:`, error);
      throw new AppError('Failed to get index stats', 500);
    }
  }
  
  /**
   * Health check
   */
  async healthCheck() {
    try {
      const health = await this.client.cluster.health();
      return {
        status: health.status,
        numberOfNodes: health.number_of_nodes,
        activeShards: health.active_shards,
        activePrimaryShards: health.active_primary_shards
      };
    } catch (error) {
      logger.error('Elasticsearch health check failed:', error);
      return {
        status: 'unavailable',
        error: error.message
      };
    }
  }
}

// Create singleton instance
const searchService = new SearchService();

module.exports = searchService;