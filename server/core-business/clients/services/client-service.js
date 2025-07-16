/**
 * @file Client Service Layer
 * @description Business logic layer for advanced client management
 * @version 2.0.0
 */

const Client = require('../models/client-model');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const mongoose = require('mongoose');
const { sendEmail } = require('../../../shared/services/email-service');
const { generatePDF } = require('../../../shared/utils/pdf-generator');
const { validateVAT } = require('../../../shared/utils/vat-validator');
const { geocodeAddress } = require('../../../shared/utils/geocoder');
const { checkSanctions } = require('../../../shared/utils/sanctions-checker');

class ClientService {
  /**
   * Create a new client with comprehensive validation
   * @param {Object} clientData - The client data
   * @param {string} userId - The ID of the user creating the client
   * @returns {Promise<Object>} - The created client
   */
  static async createClient(clientData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.debug('Starting client creation process', {
        clientName: clientData.name,
        userId,
        industry: clientData.industry?.primary
      });

      // Validate VAT number if provided
      if (clientData.companyDetails?.vatNumber) {
        const vatValidation = await validateVAT(
          clientData.companyDetails.vatNumber,
          clientData.addresses.headquarters.country
        );
        
        if (!vatValidation.valid) {
          logger.warn('Invalid VAT number provided', {
            vatNumber: clientData.companyDetails.vatNumber,
            country: clientData.addresses.headquarters.country
          });
          throw new AppError('Invalid VAT number', 400);
        }
      }

      // Geocode headquarters address
      if (clientData.addresses?.headquarters) {
        try {
          const coordinates = await geocodeAddress(clientData.addresses.headquarters);
          clientData.addresses.headquarters.coordinates = coordinates;
        } catch (geocodeError) {
          logger.warn('Geocoding failed, continuing without coordinates', {
            error: geocodeError.message,
            address: clientData.addresses.headquarters
          });
        }
      }

      // Perform sanctions check
      const sanctionsCheck = await checkSanctions(clientData.name, clientData.legalName);
      if (sanctionsCheck.matches.length > 0) {
        logger.error('Client appears on sanctions list', {
          clientName: clientData.name,
          matches: sanctionsCheck.matches
        });
        throw new AppError('Client cannot be added due to compliance restrictions', 403);
      }

      // Set compliance data
      clientData.compliance = {
        ...clientData.compliance,
        sanctions: {
          checked: true,
          checkedDate: new Date(),
          clearStatus: true
        }
      };

      // Set creator
      clientData.createdBy = userId;
      clientData.updatedBy = userId;

      // Initialize analytics
      clientData.analytics = {
        lifetimeValue: { amount: 0, currency: clientData.financial?.creditLimit?.currency || 'USD' },
        engagementScore: { score: 50, lastCalculated: new Date() }
      };

      // Create client within transaction
      const [client] = await Client.create([clientData], { session });

      // Send welcome email to primary contact
      const primaryContact = client.contactPersons.find(cp => cp.isPrimary);
      if (primaryContact?.email) {
        await this.sendWelcomeEmail(client, primaryContact);
      }

      // Create initial activity log entry
      await this.logActivity(client._id, 'client_created', {
        userId,
        clientName: client.name
      }, session);

      // Populate references for response
      await client.populate([
        { path: 'accountManagement.accountManager', select: 'firstName lastName email' },
        { path: 'createdBy', select: 'firstName lastName email' }
      ]);

      await session.commitTransaction();
      
      logger.info('Client created successfully', {
        clientId: client._id,
        clientName: client.name,
        code: client.code,
        userId
      });

      // Trigger async processes
      this.performPostCreationTasks(client._id).catch(err => {
        logger.error('Post-creation tasks failed', { clientId: client._id, error: err.message });
      });

      return client;
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Client creation failed', {
        clientName: clientData.name,
        userId,
        error: error.message,
        stack: error.stack
      });
      
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        throw new AppError(`A client with this ${field} already exists`, 400);
      }
      
      throw error instanceof AppError ? error : new AppError(`Failed to create client: ${error.message}`, 400);
    } finally {
      session.endSession();
    }
  }

  /**
   * Get all clients with advanced filtering
   * @param {Object} filter - Filter criteria
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Clients with pagination
   */
  static async getAllClients(filter = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        search,
        status,
        tier,
        industry,
        country,
        city,
        accountManager,
        tags,
        revenueRange,
        employeeRange,
        healthScoreMin,
        healthScoreMax,
        churnRisk,
        lastActivityDays,
        includeInactive = false,
        includeBlacklisted = false
      } = options;

      logger.debug('Fetching clients with filters', {
        filter,
        options: {
          page,
          limit,
          sortBy,
          search,
          status,
          tier
        }
      });

      const skip = (page - 1) * limit;
      const queryFilter = { ...filter };

      // Status filters
      if (!includeInactive) {
        queryFilter['status.isActive'] = true;
      }
      if (!includeBlacklisted) {
        queryFilter['status.blacklisted'] = false;
      }

      // Basic filters
      if (status) queryFilter['relationship.status'] = status;
      if (tier) queryFilter['relationship.tier'] = tier;
      if (industry) queryFilter['industry.primary'] = industry;
      if (accountManager) queryFilter['accountManagement.accountManager'] = accountManager;
      if (churnRisk) queryFilter['relationship.churnRisk.level'] = churnRisk;

      // Location filters
      if (country) queryFilter['addresses.headquarters.country'] = country;
      if (city) queryFilter['addresses.headquarters.city'] = city;

      // Array filters
      if (tags?.length) {
        queryFilter['internal.tags'] = { $in: tags };
      }

      // Range filters
      if (revenueRange) {
        queryFilter['companyDetails.annualRevenue.range'] = revenueRange;
      }
      if (employeeRange) {
        queryFilter['companyDetails.employeeCount.range'] = employeeRange;
      }

      // Health score filter
      if (healthScoreMin || healthScoreMax) {
        queryFilter['relationship.healthScore.score'] = {};
        if (healthScoreMin) queryFilter['relationship.healthScore.score'].$gte = healthScoreMin;
        if (healthScoreMax) queryFilter['relationship.healthScore.score'].$lte = healthScoreMax;
      }

      // Last activity filter
      if (lastActivityDays) {
        const dateThreshold = new Date();
        dateThreshold.setDate(dateThreshold.getDate() - lastActivityDays);
        queryFilter['relationship.lastActivityDate'] = { $gte: dateThreshold };
      }

      // Text search
      if (search) {
        queryFilter.$text = { $search: search };
      }

      // Build sort option
      const sortOption = {};
      if (search) {
        sortOption.score = { $meta: 'textScore' };
      }
      sortOption[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute query
      const [clients, total] = await Promise.all([
        Client.find(queryFilter)
          .sort(sortOption)
          .skip(skip)
          .limit(parseInt(limit))
          .populate('accountManagement.accountManager', 'firstName lastName email profile.avatar')
          .populate('accountManagement.secondaryManager', 'firstName lastName email')
          .select('-documents -internal.notes'),
        Client.countDocuments(queryFilter)
      ]);

      // Calculate aggregated statistics
      const stats = await this.getClientStatistics(queryFilter);

      logger.debug('Clients fetched successfully', {
        totalFound: total,
        pageSize: clients.length,
        page,
        hasFilters: Object.keys(queryFilter).length > 0
      });

      return {
        clients,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit),
          hasMore: page < Math.ceil(total / limit)
        },
        stats
      };
    } catch (error) {
      logger.error('Failed to fetch clients', {
        filter,
        options,
        error: error.message
      });
      throw new AppError(`Failed to fetch clients: ${error.message}`, 500);
    }
  }

  /**
   * Get client statistics
   * @param {Object} baseFilter - Base filter to apply
   * @returns {Promise<Object>} - Aggregated statistics
   */
  static async getClientStatistics(baseFilter = {}) {
    try {
      const stats = await Client.aggregate([
        { $match: baseFilter },
        {
          $group: {
            _id: null,
            totalClients: { $sum: 1 },
            totalLifetimeValue: { $sum: '$analytics.lifetimeValue.amount' },
            averageHealthScore: { $avg: '$relationship.healthScore.score' },
            byStatus: {
              $push: {
                status: '$relationship.status',
                tier: '$relationship.tier'
              }
            },
            byIndustry: { $push: '$industry.primary' },
            highRiskCount: {
              $sum: {
                $cond: [
                  { $in: ['$relationship.churnRisk.level', ['high', 'critical']] },
                  1,
                  0
                ]
              }
            }
          }
        },
        {
          $project: {
            totalClients: 1,
            totalLifetimeValue: 1,
            averageHealthScore: { $round: ['$averageHealthScore', 2] },
            highRiskCount: 1,
            statusBreakdown: {
              $arrayToObject: {
                $map: {
                  input: { $setUnion: ['$byStatus.status'] },
                  as: 'status',
                  in: {
                    k: '$$status',
                    v: {
                      $size: {
                        $filter: {
                          input: '$byStatus',
                          as: 'item',
                          cond: { $eq: ['$$item.status', '$$status'] }
                        }
                      }
                    }
                  }
                }
              }
            },
            tierBreakdown: {
              $arrayToObject: {
                $map: {
                  input: { $setUnion: ['$byStatus.tier'] },
                  as: 'tier',
                  in: {
                    k: '$$tier',
                    v: {
                      $size: {
                        $filter: {
                          input: '$byStatus',
                          as: 'item',
                          cond: { $eq: ['$$item.tier', '$$tier'] }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]);

      return stats[0] || {
        totalClients: 0,
        totalLifetimeValue: 0,
        averageHealthScore: 0,
        highRiskCount: 0,
        statusBreakdown: {},
        tierBreakdown: {}
      };
    } catch (error) {
      logger.error('Failed to get client statistics', {
        baseFilter,
        error: error.message
      });
      throw new AppError(`Failed to get client statistics: ${error.message}`, 500);
    }
  }

  /**
   * Get client by ID with full details
   * @param {string} clientId - The client ID
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} - The client
   */
  static async getClientById(clientId, options = {}) {
    try {
      const { includeNotes = false, includeDocuments = false } = options;

      logger.debug('Fetching client by ID', {
        clientId,
        includeNotes,
        includeDocuments
      });

      let query = Client.findById(clientId);

      // Conditional field exclusion
      if (!includeNotes) {
        query = query.select('-internal.notes');
      }
      if (!includeDocuments) {
        query = query.select('-documents');
      }

      const client = await query
        .populate('accountManagement.accountManager', 'firstName lastName email profile')
        .populate('accountManagement.secondaryManager', 'firstName lastName email')
        .populate('accountManagement.salesRep', 'firstName lastName email')
        .populate('accountManagement.customerSuccessManager', 'firstName lastName email')
        .populate('accountManagement.team.member', 'firstName lastName email profile.title')
        .populate('createdBy', 'firstName lastName email')
        .populate('updatedBy', 'firstName lastName email');

      if (!client) {
        logger.warn('Client not found', { clientId });
        throw new AppError('Client not found', 404);
      }

      logger.debug('Client fetched successfully', {
        clientId: client._id,
        clientName: client.name,
        code: client.code
      });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      if (error.name === 'CastError') {
        logger.warn('Invalid client ID format', { clientId });
        throw new AppError('Invalid client ID', 400);
      }
      logger.error('Failed to fetch client by ID', {
        clientId,
        error: error.message
      });
      throw new AppError(`Failed to fetch client: ${error.message}`, 500);
    }
  }

  /**
   * Get client by code
   * @param {string} code - The client code
   * @returns {Promise<Object>} - The client
   */
  static async getClientByCode(code) {
    try {
      logger.debug('Fetching client by code', { code });

      const client = await Client.findOne({ code: code.toUpperCase() })
        .populate('accountManagement.accountManager', 'firstName lastName email profile')
        .select('-internal.notes -documents');

      if (!client) {
        logger.warn('Client not found by code', { code });
        throw new AppError('Client not found', 404);
      }

      logger.debug('Client fetched by code successfully', {
        clientId: client._id,
        clientName: client.name,
        code: client.code
      });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to fetch client by code', {
        code,
        error: error.message
      });
      throw new AppError(`Failed to fetch client: ${error.message}`, 500);
    }
  }

  /**
   * Update client with validation
   * @param {string} clientId - The client ID
   * @param {Object} updateData - The update data
   * @param {string} userId - The ID of the user updating
   * @returns {Promise<Object>} - The updated client
   */
  static async updateClient(clientId, updateData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.debug('Updating client', {
        clientId,
        userId,
        updateFields: Object.keys(updateData)
      });

      // Get current client to check for changes
      const currentClient = await Client.findById(clientId).session(session);
      if (!currentClient) {
        throw new AppError('Client not found', 404);
      }

      // Set updater
      updateData.updatedBy = userId;

      // Don't allow direct modification of certain fields
      delete updateData.code;
      delete updateData.analytics;
      delete updateData.dataQuality;
      delete updateData.createdBy;

      // Validate VAT number if changed
      if (updateData.companyDetails?.vatNumber && 
          updateData.companyDetails.vatNumber !== currentClient.companyDetails.vatNumber) {
        const country = updateData.addresses?.headquarters?.country || 
                       currentClient.addresses.headquarters.country;
        const vatValidation = await validateVAT(updateData.companyDetails.vatNumber, country);
        
        if (!vatValidation.valid) {
          throw new AppError('Invalid VAT number', 400);
        }
      }

      // Re-geocode if address changed
      if (updateData.addresses?.headquarters) {
        const addressChanged = ['street1', 'street2', 'city', 'state', 'postalCode', 'country']
          .some(field => updateData.addresses.headquarters[field] !== currentClient.addresses.headquarters[field]);
        
        if (addressChanged) {
          try {
            const coordinates = await geocodeAddress(updateData.addresses.headquarters);
            updateData.addresses.headquarters.coordinates = coordinates;
          } catch (geocodeError) {
            logger.warn('Geocoding failed during update', {
              error: geocodeError.message,
              clientId
            });
          }
        }
      }

      // Check sanctions if name changed
      if (updateData.name && updateData.name !== currentClient.name) {
        const sanctionsCheck = await checkSanctions(updateData.name, updateData.legalName);
        if (sanctionsCheck.matches.length > 0) {
          throw new AppError('Client cannot be updated due to compliance restrictions', 403);
        }
        
        updateData.compliance = {
          ...currentClient.compliance,
          sanctions: {
            checked: true,
            checkedDate: new Date(),
            clearStatus: true
          }
        };
      }

      const client = await Client.findByIdAndUpdate(
        clientId,
        updateData,
        { 
          new: true, 
          runValidators: true,
          session
        }
      );

      await client.populate([
        { path: 'accountManagement.accountManager', select: 'firstName lastName email' },
        { path: 'updatedBy', select: 'firstName lastName email' }
      ]);

      // Log significant changes
      const significantChanges = this.detectSignificantChanges(currentClient, client);
      if (significantChanges.length > 0) {
        await this.logActivity(clientId, 'client_updated', {
          userId,
          changes: significantChanges
        }, session);
      }

      await session.commitTransaction();
      
      logger.info('Client updated successfully', {
        clientId: client._id,
        clientName: client.name,
        userId,
        changesCount: significantChanges.length
      });

      // Trigger async processes
      if (significantChanges.some(change => change.field === 'relationship.status')) {
        this.handleStatusChange(client).catch(err => {
          logger.error('Status change handling failed', { clientId, error: err.message });
        });
      }

      return client;
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Client update failed', {
        clientId,
        userId,
        error: error.message
      });
      
      if (error instanceof AppError) throw error;
      if (error.name === 'CastError') {
        throw new AppError('Invalid client ID', 400);
      }
      
      throw new AppError(`Failed to update client: ${error.message}`, 500);
    } finally {
      session.endSession();
    }
  }

  /**
   * Add contact person to client
   * @param {string} clientId - The client ID
   * @param {Object} contactData - Contact person data
   * @param {string} userId - User adding the contact
   * @returns {Promise<Object>} - Updated client
   */
  static async addContactPerson(clientId, contactData, userId) {
    try {
      logger.debug('Adding contact person to client', {
        clientId,
        contactEmail: contactData.email,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      // Check if email already exists
      const emailExists = client.contactPersons.some(cp => cp.email === contactData.email);
      if (emailExists) {
        throw new AppError('A contact with this email already exists', 400);
      }

      // If setting as primary, unset other primary contacts
      if (contactData.isPrimary) {
        client.contactPersons.forEach(cp => { cp.isPrimary = false; });
      }

      client.contactPersons.push(contactData);
      client.updatedBy = userId;

      await client.save();

      logger.info('Contact person added successfully', {
        clientId,
        contactEmail: contactData.email,
        isPrimary: contactData.isPrimary,
        userId
      });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to add contact person', {
        clientId,
        contactData,
        error: error.message
      });
      throw new AppError(`Failed to add contact person: ${error.message}`, 500);
    }
  }

  /**
   * Update contact person
   * @param {string} clientId - The client ID
   * @param {string} contactId - The contact person ID
   * @param {Object} updateData - Update data
   * @param {string} userId - User updating the contact
   * @returns {Promise<Object>} - Updated client
   */
  static async updateContactPerson(clientId, contactId, updateData, userId) {
    try {
      logger.debug('Updating contact person', {
        clientId,
        contactId,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      const contact = client.contactPersons.id(contactId);
      if (!contact) {
        throw new AppError('Contact person not found', 404);
      }

      // If setting as primary, unset other primary contacts
      if (updateData.isPrimary && !contact.isPrimary) {
        client.contactPersons.forEach(cp => { 
          if (cp._id.toString() !== contactId) {
            cp.isPrimary = false;
          }
        });
      }

      // Update contact fields
      Object.assign(contact, updateData);
      contact.lastContactedAt = new Date();
      client.updatedBy = userId;

      await client.save();

      logger.info('Contact person updated successfully', {
        clientId,
        contactId,
        userId
      });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to update contact person', {
        clientId,
        contactId,
        error: error.message
      });
      throw new AppError(`Failed to update contact person: ${error.message}`, 500);
    }
  }

  /**
   * Remove contact person
   * @param {string} clientId - The client ID
   * @param {string} contactId - The contact person ID
   * @param {string} userId - User removing the contact
   * @returns {Promise<Object>} - Updated client
   */
  static async removeContactPerson(clientId, contactId, userId) {
    try {
      logger.debug('Removing contact person', {
        clientId,
        contactId,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      const contact = client.contactPersons.id(contactId);
      if (!contact) {
        throw new AppError('Contact person not found', 404);
      }

      // Don't allow removal of last contact
      if (client.contactPersons.length === 1) {
        throw new AppError('Cannot remove the last contact person', 400);
      }

      // If removing primary contact, make another one primary
      if (contact.isPrimary && client.contactPersons.length > 1) {
        const newPrimary = client.contactPersons.find(cp => 
          cp._id.toString() !== contactId && cp.active
        );
        if (newPrimary) {
          newPrimary.isPrimary = true;
        }
      }

      contact.remove();
      client.updatedBy = userId;

      await client.save();

      logger.info('Contact person removed successfully', {
        clientId,
        contactId,
        userId
      });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to remove contact person', {
        clientId,
        contactId,
        error: error.message
      });
      throw new AppError(`Failed to remove contact person: ${error.message}`, 500);
    }
  }

  /**
   * Update client status
   * @param {string} clientId - The client ID
   * @param {string} status - New status
   * @param {string} userId - User making the change
   * @param {Object} additionalData - Additional data for status change
   * @returns {Promise<Object>} - Updated client
   */
  static async updateClientStatus(clientId, status, userId, additionalData = {}) {
    try {
      logger.debug('Updating client status', {
        clientId,
        oldStatus: 'unknown',
        newStatus: status,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      const oldStatus = client.relationship.status;
      client.relationship.status = status;
      client.relationship.lastActivityDate = new Date();
      client.updatedBy = userId;

      // Handle status-specific logic
      switch (status) {
        case 'active':
          client.status.isActive = true;
          if (oldStatus === 'prospect' || oldStatus === 'lead') {
            client.relationship.startDate = new Date();
          }
          break;
          
        case 'inactive':
        case 'dormant':
          // Calculate and set renewal date if needed
          if (additionalData.renewalDate) {
            client.relationship.renewalDate = additionalData.renewalDate;
          }
          break;
          
        case 'lost':
          client.status.isActive = false;
          client.relationship.churnRisk.level = 'critical';
          if (additionalData.lostReason) {
            client.relationship.churnRisk.reasons = [additionalData.lostReason];
          }
          break;
          
        case 'blacklisted':
          await client.blacklist(additionalData.reason || 'Status changed to blacklisted', userId);
          break;
      }

      await client.save();

      // Log activity
      await this.logActivity(clientId, 'status_changed', {
        userId,
        oldStatus,
        newStatus: status,
        reason: additionalData.reason
      });

      logger.info('Client status updated successfully', {
        clientId: client._id,
        clientName: client.name,
        oldStatus,
        newStatus: status,
        userId
      });

      // Send notifications based on status change
      await this.handleStatusChange(client, oldStatus);

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to update client status', {
        clientId,
        status,
        userId,
        error: error.message
      });
      throw new AppError(`Failed to update client status: ${error.message}`, 500);
    }
  }

  /**
   * Suspend client
   * @param {string} clientId - The client ID
   * @param {string} reason - Suspension reason
   * @param {string} userId - User performing suspension
   * @returns {Promise<Object>} - Updated client
   */
  static async suspendClient(clientId, reason, userId) {
    try {
      logger.info('Suspending client', {
        clientId,
        reason,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      if (client.status.blacklisted) {
        throw new AppError('Cannot suspend a blacklisted client', 400);
      }

      await client.suspend(reason, userId);

      // Log activity
      await this.logActivity(clientId, 'client_suspended', {
        userId,
        reason
      });

      logger.info('Client suspended successfully', {
        clientId: client._id,
        clientName: client.name,
        reason,
        userId
      });

      // Notify account manager
      await this.notifyAccountManager(client, 'suspension', { reason });

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to suspend client', {
        clientId,
        reason,
        userId,
        error: error.message
      });
      throw new AppError(`Failed to suspend client: ${error.message}`, 500);
    }
  }

  /**
   * Reactivate client
   * @param {string} clientId - The client ID
   * @param {string} userId - User performing reactivation
   * @returns {Promise<Object>} - Updated client
   */
  static async reactivateClient(clientId, userId) {
    try {
      logger.info('Reactivating client', {
        clientId,
        userId
      });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      if (client.status.blacklisted) {
        throw new AppError('Cannot reactivate a blacklisted client', 400);
      }

      await client.reactivate();
      client.updatedBy = userId;
      await client.save();

      // Log activity
      await this.logActivity(clientId, 'client_reactivated', {
        userId
      });

      logger.info('Client reactivated successfully', {
        clientId: client._id,
        clientName: client.name,
        userId
      });

      // Notify account manager
      await this.notifyAccountManager(client, 'reactivation');

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to reactivate client', {
        clientId,
        userId,
        error: error.message
      });
      throw new AppError(`Failed to reactivate client: ${error.message}`, 500);
    }
  }

  /**
   * Get high-risk clients
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - High-risk clients
   */
  static async getHighRiskClients(options = {}) {
    try {
      const { 
        limit = 20,
        includeReasons = true,
        assignedTo 
      } = options;

      logger.debug('Fetching high-risk clients', {
        limit,
        includeReasons,
        assignedTo
      });

      let query = Client.findHighRiskClients();

      if (assignedTo) {
        query = query.where('accountManagement.accountManager', assignedTo);
      }

      const clients = await query
        .limit(limit)
        .select('name code relationship.status relationship.healthScore relationship.churnRisk accountManagement analytics.lifetimeValue');

      // Enrich with recommended actions
      const enrichedClients = clients.map(client => ({
        ...client.toObject(),
        recommendedActions: this.generateRiskMitigationActions(client)
      }));

      logger.debug('High-risk clients fetched successfully', {
        count: enrichedClients.length,
        assignedTo
      });

      return enrichedClients;
    } catch (error) {
      logger.error('Failed to fetch high-risk clients', {
        options,
        error: error.message
      });
      throw new AppError(`Failed to fetch high-risk clients: ${error.message}`, 500);
    }
  }

  /**
   * Update client health score
   * @param {string} clientId - The client ID
   * @returns {Promise<Object>} - Updated client with new health score
   */
  static async updateClientHealthScore(clientId) {
    try {
      logger.debug('Updating client health score', { clientId });

      const client = await Client.findById(clientId);
      if (!client) {
        throw new AppError('Client not found', 404);
      }

      const oldScore = client.relationship.healthScore.score;
      await client.updateHealthScore();

      const newScore = client.relationship.healthScore.score;
      const scoreDiff = newScore - oldScore;

      logger.info('Client health score updated', {
        clientId: client._id,
        clientName: client.name,
        oldScore,
        newScore,
        difference: scoreDiff
      });

      // Alert if score dropped significantly
      if (scoreDiff < -20) {
        await this.createHealthScoreAlert(client, oldScore, newScore);
      }

      return client;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to update health score', {
        clientId,
        error: error.message
      });
      throw new AppError(`Failed to update health score: ${error.message}`, 500);
    }
  }

  /**
   * Bulk update client health scores
   * @returns {Promise<Object>} - Update results
   */
  static async bulkUpdateHealthScores() {
    try {
      logger.info('Starting bulk health score update');

      const clients = await Client.find({
        'status.isActive': true,
        'status.blacklisted': false
      }).select('_id name relationship projectStats analytics');

      let updated = 0;
      let failed = 0;
      const alerts = [];

      for (const client of clients) {
        try {
          const oldScore = client.relationship.healthScore.score;
          await client.updateHealthScore();
          const newScore = client.relationship.healthScore.score;

          if (Math.abs(newScore - oldScore) > 20) {
            alerts.push({
              clientId: client._id,
              clientName: client.name,
              oldScore,
              newScore,
              change: newScore - oldScore
            });
          }

          updated++;
        } catch (err) {
          logger.error('Failed to update health score for client', {
            clientId: client._id,
            error: err.message
          });
          failed++;
        }
      }

      logger.info('Bulk health score update completed', {
        total: clients.length,
        updated,
        failed,
        alertsGenerated: alerts.length
      });

      return {
        total: clients.length,
        updated,
        failed,
        alerts
      };
    } catch (error) {
      logger.error('Bulk health score update failed', {
        error: error.message
      });
      throw new AppError(`Bulk health score update failed: ${error.message}`, 500);
    }
  }

  /**
   * Get client engagement timeline
   * @param {string} clientId - The client ID
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} - Engagement timeline
   */
  static async getClientEngagementTimeline(clientId, startDate, endDate) {
    try {
      logger.debug('Fetching client engagement timeline', {
        clientId,
        startDate,
        endDate
      });

      const client = await Client.findById(clientId)
        .select('name code relationship');

      if (!client) {
        throw new AppError('Client not found', 404);
      }

      // Here you would aggregate data from various sources:
      // - Projects
      // - Communications
      // - Meetings
      // - Support tickets
      // - Invoices

      const timeline = {
        client: {
          id: client._id,
          name: client.name,
          code: client.code
        },
        period: {
          start: startDate,
          end: endDate
        },
        events: [], // Would be populated from various sources
        summary: {
          totalInteractions: 0,
          projectsActive: 0,
          invoicesSent: 0,
          meetingsHeld: 0
        }
      };

      logger.debug('Client engagement timeline fetched successfully', {
        clientId,
        eventsCount: timeline.events.length
      });

      return timeline;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to fetch engagement timeline', {
        clientId,
        error: error.message
      });
      throw new AppError(`Failed to fetch engagement timeline: ${error.message}`, 500);
    }
  }

  /**
   * Merge duplicate clients
   * @param {string} primaryClientId - Primary client to keep
   * @param {string} secondaryClientId - Client to merge into primary
   * @param {string} userId - User performing merge
   * @returns {Promise<Object>} - Merged client
   */
  static async mergeClients(primaryClientId, secondaryClientId, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Merging clients', {
        primaryClientId,
        secondaryClientId,
        userId
      });

      if (primaryClientId === secondaryClientId) {
        throw new AppError('Cannot merge a client with itself', 400);
      }

      const [primaryClient, secondaryClient] = await Promise.all([
        Client.findById(primaryClientId).session(session),
        Client.findById(secondaryClientId).session(session)
      ]);

      if (!primaryClient || !secondaryClient) {
        throw new AppError('One or both clients not found', 404);
      }

      // Merge contact persons
      const existingEmails = primaryClient.contactPersons.map(cp => cp.email);
      const newContacts = secondaryClient.contactPersons.filter(cp => 
        !existingEmails.includes(cp.email)
      );
      primaryClient.contactPersons.push(...newContacts);

      // Merge tags
      const existingTags = new Set(primaryClient.internal.tags);
      secondaryClient.internal.tags.forEach(tag => existingTags.add(tag));
      primaryClient.internal.tags = Array.from(existingTags);

      // Merge notes
      primaryClient.internal.notes.push(...secondaryClient.internal.notes.map(note => ({
        ...note.toObject(),
        content: `[Merged from ${secondaryClient.name}] ${note.content}`
      })));

      // Update financial data (take the better terms)
      if (secondaryClient.financial.creditLimit.amount > primaryClient.financial.creditLimit.amount) {
        primaryClient.financial.creditLimit = secondaryClient.financial.creditLimit;
      }

      // Update analytics (sum values)
      primaryClient.analytics.lifetimeValue.amount += secondaryClient.analytics.lifetimeValue.amount;
      primaryClient.projectStats.totalProjects += secondaryClient.projectStats.totalProjects;
      primaryClient.projectStats.completedProjects += secondaryClient.projectStats.completedProjects;
      primaryClient.projectStats.totalValue.amount += secondaryClient.projectStats.totalValue.amount;

      // Record merge
      primaryClient.mergedFrom.push({
        clientId: secondaryClient._id,
        mergedAt: new Date(),
        mergedBy: userId
      });

      primaryClient.updatedBy = userId;

      // Update all references to secondary client
      // This would include updating projects, invoices, etc.
      // await this.updateClientReferences(secondaryClientId, primaryClientId, session);

      // Archive secondary client
      secondaryClient.status.isActive = false;
      secondaryClient.internal.notes.push({
        content: `Client merged into ${primaryClient.name} (${primaryClient.code})`,
        type: 'general',
        author: userId,
        isPinned: true
      });

      await Promise.all([
        primaryClient.save({ session }),
        secondaryClient.save({ session })
      ]);

      await session.commitTransaction();

      logger.info('Clients merged successfully', {
        primaryClientId: primaryClient._id,
        secondaryClientId: secondaryClient._id,
        primaryClientName: primaryClient.name,
        userId
      });

      return primaryClient;
    } catch (error) {
      await session.abortTransaction();
      
      if (error instanceof AppError) throw error;
      logger.error('Client merge failed', {
        primaryClientId,
        secondaryClientId,
        userId,
        error: error.message
      });
      throw new AppError(`Failed to merge clients: ${error.message}`, 500);
    } finally {
      session.endSession();
    }
  }

  /**
   * Export clients data
   * @param {Object} filter - Filter criteria
   * @param {Array} fields - Fields to export
   * @param {string} format - Export format
   * @returns {Promise<Object>} - Exported data
   */
  static async exportClients(filter = {}, fields = [], format = 'json') {
    try {
      logger.debug('Exporting clients', {
        filter,
        fieldCount: fields.length,
        format
      });

      // Default fields if none specified
      if (fields.length === 0) {
        fields = [
          'name', 'code', 'legalName', 'companyDetails.type',
          'industry.primary', 'addresses.headquarters.country',
          'relationship.status', 'relationship.tier',
          'contactPersons', 'accountManagement.accountManager'
        ];
      }

      const projection = fields.reduce((acc, field) => {
        acc[field] = 1;
        return acc;
      }, {});

      const clients = await Client.find(filter)
        .select(projection)
        .populate('accountManagement.accountManager', 'firstName lastName email')
        .lean();

      // Format data based on export format
      let exportData;
      switch (format) {
        case 'csv':
          exportData = this.convertToCSV(clients, fields);
          break;
        case 'xlsx':
          exportData = await this.convertToExcel(clients, fields);
          break;
        default:
          exportData = clients;
      }

      logger.info('Clients exported successfully', {
        filter,
        exportedCount: clients.length,
        format
      });

      return {
        data: exportData,
        count: clients.length,
        format,
        fields
      };
    } catch (error) {
      logger.error('Export failed', {
        filter,
        format,
        error: error.message
      });
      throw new AppError(`Export failed: ${error.message}`, 500);
    }
  }

  /**
   * Import clients from external source
   * @param {Array} clientsData - Array of client data
   * @param {Object} options - Import options
   * @param {string} userId - User performing import
   * @returns {Promise<Object>} - Import results
   */
  static async importClients(clientsData, options = {}, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const {
        updateExisting = false,
        validateOnly = false,
        source = 'manual'
      } = options;

      logger.info('Starting client import', {
        count: clientsData.length,
        updateExisting,
        validateOnly,
        source,
        userId
      });

      const results = {
        total: clientsData.length,
        successful: 0,
        failed: 0,
        updated: 0,
        errors: []
      };

      for (const [index, clientData] of clientsData.entries()) {
        try {
          // Check for existing client
          const existingClient = await Client.findOne({
            $or: [
              { code: clientData.code },
              { 'companyDetails.registrationNumber': clientData.companyDetails?.registrationNumber },
              { 'contacts.main.email': clientData.contacts?.main?.email }
            ]
          }).session(session);

          if (existingClient) {
            if (updateExisting) {
              if (!validateOnly) {
                await this.updateClient(existingClient._id, clientData, userId);
              }
              results.updated++;
            } else {
              throw new Error(`Client already exists: ${existingClient.name} (${existingClient.code})`);
            }
          } else {
            if (!validateOnly) {
              clientData.importedFrom = {
                system: source,
                id: clientData.externalId || `import-${index}`,
                date: new Date()
              };
              await this.createClient(clientData, userId);
            }
            results.successful++;
          }
        } catch (error) {
          results.failed++;
          results.errors.push({
            row: index + 1,
            client: clientData.name || 'Unknown',
            error: error.message
          });
          
          if (!options.continueOnError) {
            throw error;
          }
        }
      }

      if (validateOnly) {
        await session.abortTransaction();
      } else {
        await session.commitTransaction();
      }

      logger.info('Client import completed', {
        ...results,
        validateOnly,
        userId
      });

      return results;
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Client import failed', {
        error: error.message,
        userId
      });
      throw new AppError(`Import failed: ${error.message}`, 500);
    } finally {
      session.endSession();
    }
  }

  // Helper methods

  /**
   * Send welcome email to new client
   * @private
   */
  static async sendWelcomeEmail(client, contact) {
    try {
      await sendEmail({
        to: contact.email,
        subject: `Welcome to Our Services, ${client.name}!`,
        template: 'client-welcome',
        data: {
          clientName: client.name,
          contactName: `${contact.firstName} ${contact.lastName}`,
          accountManager: client.accountManagement.accountManager
        }
      });
    } catch (error) {
      logger.error('Failed to send welcome email', {
        clientId: client._id,
        contactEmail: contact.email,
        error: error.message
      });
    }
  }

  /**
   * Detect significant changes in client data
   * @private
   */
  static detectSignificantChanges(oldClient, newClient) {
    const significantFields = [
      'name', 'legalName', 'relationship.status', 'relationship.tier',
      'accountManagement.accountManager', 'financial.creditLimit',
      'addresses.headquarters'
    ];

    const changes = [];
    
    significantFields.forEach(field => {
      const oldValue = field.includes('.') ? 
        field.split('.').reduce((obj, key) => obj?.[key], oldClient) :
        oldClient[field];
      const newValue = field.includes('.') ? 
        field.split('.').reduce((obj, key) => obj?.[key], newClient) :
        newClient[field];
      
      if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
        changes.push({
          field,
          oldValue,
          newValue
        });
      }
    });

    return changes;
  }

  /**
   * Handle status change notifications and actions
   * @private
   */
  static async handleStatusChange(client, oldStatus) {
    try {
      const newStatus = client.relationship.status;
      
      // Send notifications based on status transitions
      if (oldStatus === 'prospect' && newStatus === 'active') {
        await this.notifyAccountManager(client, 'new_active_client');
      } else if (newStatus === 'lost') {
        await this.notifyAccountManager(client, 'client_lost');
      } else if (newStatus === 'blacklisted') {
        await this.notifyCompliance(client, 'client_blacklisted');
      }
    } catch (error) {
      logger.error('Failed to handle status change', {
        clientId: client._id,
        error: error.message
      });
    }
  }

  /**
   * Generate risk mitigation actions
   * @private
   */
  static generateRiskMitigationActions(client) {
    const actions = [];
    const { healthScore, churnRisk } = client.relationship;

    if (healthScore.factors.engagementLevel < 30) {
      actions.push({
        priority: 'high',
        action: 'Schedule executive business review',
        reason: 'Low engagement level'
      });
    }

    if (healthScore.factors.satisfactionScore < 50) {
      actions.push({
        priority: 'high',
        action: 'Conduct satisfaction survey and address concerns',
        reason: 'Low satisfaction score'
      });
    }

    if (churnRisk.level === 'critical') {
      actions.push({
        priority: 'critical',
        action: 'Immediate escalation to senior management',
        reason: 'Critical churn risk'
      });
    }

    return actions;
  }

  /**
   * Notify account manager
   * @private
   */
  static async notifyAccountManager(client, eventType, data = {}) {
    try {
      // Implementation would depend on your notification system
      logger.debug('Notifying account manager', {
        clientId: client._id,
        eventType,
        accountManager: client.accountManagement.accountManager
      });
    } catch (error) {
      logger.error('Failed to notify account manager', {
        clientId: client._id,
        eventType,
        error: error.message
      });
    }
  }

  /**
   * Notify compliance team
   * @private
   */
  static async notifyCompliance(client, eventType, data = {}) {
    try {
      logger.debug('Notifying compliance team', {
        clientId: client._id,
        eventType
      });
    } catch (error) {
      logger.error('Failed to notify compliance', {
        clientId: client._id,
        eventType,
        error: error.message
      });
    }
  }

  /**
   * Log client activity
   * @private
   */
  static async logActivity(clientId, activityType, data, session = null) {
    try {
      // This would log to your activity tracking system
      logger.debug('Logging client activity', {
        clientId,
        activityType,
        data
      });
    } catch (error) {
      logger.error('Failed to log activity', {
        clientId,
        activityType,
        error: error.message
      });
    }
  }

  /**
   * Create health score alert
   * @private
   */
  static async createHealthScoreAlert(client, oldScore, newScore) {
    try {
      logger.info('Creating health score alert', {
        clientId: client._id,
        clientName: client.name,
        oldScore,
        newScore,
        drop: oldScore - newScore
      });
      
      // Implementation would create alert in your system
    } catch (error) {
      logger.error('Failed to create health score alert', {
        clientId: client._id,
        error: error.message
      });
    }
  }

  /**
   * Convert clients to CSV format
   * @private
   */
  static convertToCSV(clients, fields) {
    // Implementation would convert to CSV
    return clients; // Placeholder
  }

  /**
   * Convert clients to Excel format
   * @private
   */
  static async convertToExcel(clients, fields) {
    // Implementation would convert to Excel
    return clients; // Placeholder
  }

  /**
   * Perform post-creation tasks
   * @private
   */
  static async performPostCreationTasks(clientId) {
    try {
      // Update search index
      // Sync with CRM
      // Create default project structure
      // Send notifications
      
      logger.debug('Post-creation tasks completed', { clientId });
    } catch (error) {
      logger.error('Post-creation tasks failed', {
        clientId,
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = ClientService;