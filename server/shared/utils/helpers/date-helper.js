// /server/shared/utils/helpers/date-helper.js

/**
 * @file Date Helper
 * @description Date formatting and manipulation utilities
 * @version 1.0.0
 */

const moment = require('moment-timezone');
const config = require('../../config');

/**
 * Date Helper Class
 */
class DateHelper {
  constructor() {
    this.defaultTimezone = config.app.defaultTimezone || 'UTC';
    this.defaultLocale = config.app.defaultLocale || 'en';
    
    // Set default locale
    moment.locale(this.defaultLocale);
  }
  
  /**
   * Format date with various options
   * @param {Date|string|number} date - Date to format
   * @param {string} format - Format string
   * @param {Object} options - Formatting options
   * @returns {string} Formatted date
   */
  format(date, format = 'YYYY-MM-DD', options = {}) {
    const {
      timezone = this.defaultTimezone,
      locale = this.defaultLocale
    } = options;
    
    return moment(date)
      .tz(timezone)
      .locale(locale)
      .format(format);
  }
  
  /**
   * Format date relative to now (e.g., "2 hours ago")
   * @param {Date|string|number} date - Date to format
   * @param {Object} options - Formatting options
   * @returns {string} Relative time string
   */
  fromNow(date, options = {}) {
    const {
      timezone = this.defaultTimezone,
      locale = this.defaultLocale,
      withoutSuffix = false
    } = options;
    
    return moment(date)
      .tz(timezone)
      .locale(locale)
      .fromNow(withoutSuffix);
  }
  
  /**
   * Format date as time ago with custom thresholds
   * @param {Date|string|number} date - Date to format
   * @returns {string} Formatted time ago string
   */
  timeAgo(date) {
    const now = moment();
    const then = moment(date);
    const diffSeconds = now.diff(then, 'seconds');
    const diffMinutes = now.diff(then, 'minutes');
    const diffHours = now.diff(then, 'hours');
    const diffDays = now.diff(then, 'days');
    const diffWeeks = now.diff(then, 'weeks');
    const diffMonths = now.diff(then, 'months');
    const diffYears = now.diff(then, 'years');
    
    if (diffSeconds < 60) {
      return 'Just now';
    } else if (diffMinutes < 60) {
      return `${diffMinutes} ${diffMinutes === 1 ? 'minute' : 'minutes'} ago`;
    } else if (diffHours < 24) {
      return `${diffHours} ${diffHours === 1 ? 'hour' : 'hours'} ago`;
    } else if (diffDays < 7) {
      return `${diffDays} ${diffDays === 1 ? 'day' : 'days'} ago`;
    } else if (diffWeeks < 4) {
      return `${diffWeeks} ${diffWeeks === 1 ? 'week' : 'weeks'} ago`;
    } else if (diffMonths < 12) {
      return `${diffMonths} ${diffMonths === 1 ? 'month' : 'months'} ago`;
    } else {
      return `${diffYears} ${diffYears === 1 ? 'year' : 'years'} ago`;
    }
  }
  
  /**
   * Format duration between two dates
   * @param {Date|string|number} start - Start date
   * @param {Date|string|number} end - End date
   * @param {string} unit - Unit of measurement
   * @returns {string} Formatted duration
   */
  duration(start, end, unit = 'human') {
    const startMoment = moment(start);
    const endMoment = moment(end);
    const duration = moment.duration(endMoment.diff(startMoment));
    
    if (unit === 'human') {
      return duration.humanize();
    }
    
    switch (unit) {
      case 'seconds':
        return `${duration.asSeconds()} seconds`;
      case 'minutes':
        return `${Math.floor(duration.asMinutes())} minutes`;
      case 'hours':
        return `${Math.floor(duration.asHours())} hours`;
      case 'days':
        return `${Math.floor(duration.asDays())} days`;
      case 'detailed':
        const parts = [];
        const days = Math.floor(duration.asDays());
        const hours = duration.hours();
        const minutes = duration.minutes();
        
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        
        return parts.join(' ') || '0m';
      default:
        return duration.as(unit);
    }
  }
  
  /**
   * Get date range for common periods
   * @param {string} period - Period name
   * @param {Object} options - Range options
   * @returns {Object} Start and end dates
   */
  getDateRange(period, options = {}) {
    const {
      timezone = this.defaultTimezone,
      includeTime = false
    } = options;
    
    const now = moment.tz(timezone);
    let start, end;
    
    switch (period) {
      case 'today':
        start = now.clone().startOf('day');
        end = now.clone().endOf('day');
        break;
        
      case 'yesterday':
        start = now.clone().subtract(1, 'day').startOf('day');
        end = now.clone().subtract(1, 'day').endOf('day');
        break;
        
      case 'thisWeek':
        start = now.clone().startOf('week');
        end = now.clone().endOf('week');
        break;
        
      case 'lastWeek':
        start = now.clone().subtract(1, 'week').startOf('week');
        end = now.clone().subtract(1, 'week').endOf('week');
        break;
        
      case 'thisMonth':
        start = now.clone().startOf('month');
        end = now.clone().endOf('month');
        break;
        
      case 'lastMonth':
        start = now.clone().subtract(1, 'month').startOf('month');
        end = now.clone().subtract(1, 'month').endOf('month');
        break;
        
      case 'thisQuarter':
        start = now.clone().startOf('quarter');
        end = now.clone().endOf('quarter');
        break;
        
      case 'lastQuarter':
        start = now.clone().subtract(1, 'quarter').startOf('quarter');
        end = now.clone().subtract(1, 'quarter').endOf('quarter');
        break;
        
      case 'thisYear':
        start = now.clone().startOf('year');
        end = now.clone().endOf('year');
        break;
        
      case 'lastYear':
        start = now.clone().subtract(1, 'year').startOf('year');
        end = now.clone().subtract(1, 'year').endOf('year');
        break;
        
      case 'last7Days':
        start = now.clone().subtract(6, 'days').startOf('day');
        end = now.clone().endOf('day');
        break;
        
      case 'last30Days':
        start = now.clone().subtract(29, 'days').startOf('day');
        end = now.clone().endOf('day');
        break;
        
      case 'last90Days':
        start = now.clone().subtract(89, 'days').startOf('day');
        end = now.clone().endOf('day');
        break;
        
      case 'last365Days':
        start = now.clone().subtract(364, 'days').startOf('day');
        end = now.clone().endOf('day');
        break;
        
      default:
        throw new Error(`Unknown period: ${period}`);
    }
    
    const format = includeTime ? 'YYYY-MM-DD HH:mm:ss' : 'YYYY-MM-DD';
    
    return {
      start: start.format(format),
      end: end.format(format),
      startDate: start.toDate(),
      endDate: end.toDate()
    };
  }
  
  /**
   * Convert between timezones
   * @param {Date|string|number} date - Date to convert
   * @param {string} fromTimezone - Source timezone
   * @param {string} toTimezone - Target timezone
   * @returns {Object} Converted date information
   */
  convertTimezone(date, fromTimezone, toTimezone) {
    const m = moment.tz(date, fromTimezone);
    const converted = m.clone().tz(toTimezone);
    
    return {
      original: m.format(),
      converted: converted.format(),
      offset: converted.utcOffset(),
      offsetString: converted.format('Z'),
      date: converted.toDate()
    };
  }
  
  /**
   * Get working days between two dates
   * @param {Date|string|number} start - Start date
   * @param {Date|string|number} end - End date
   * @param {Array} holidays - Array of holiday dates
   * @returns {number} Number of working days
   */
  getWorkingDays(start, end, holidays = []) {
    const startDate = moment(start);
    const endDate = moment(end);
    const holidayDates = holidays.map(h => moment(h).format('YYYY-MM-DD'));
    
    let workingDays = 0;
    const current = startDate.clone();
    
    while (current.isSameOrBefore(endDate)) {
      const dayOfWeek = current.day();
      const dateString = current.format('YYYY-MM-DD');
      
      // Check if it's a weekday and not a holiday
      if (dayOfWeek !== 0 && dayOfWeek !== 6 && !holidayDates.includes(dateString)) {
        workingDays++;
      }
      
      current.add(1, 'day');
    }
    
    return workingDays;
  }
  
  /**
   * Add working days to a date
   * @param {Date|string|number} date - Start date
   * @param {number} days - Number of working days to add
   * @param {Array} holidays - Array of holiday dates
   * @returns {Date} Result date
   */
  addWorkingDays(date, days, holidays = []) {
    const result = moment(date);
    const holidayDates = holidays.map(h => moment(h).format('YYYY-MM-DD'));
    
    let addedDays = 0;
    
    while (addedDays < days) {
      result.add(1, 'day');
      
      const dayOfWeek = result.day();
      const dateString = result.format('YYYY-MM-DD');
      
      // Check if it's a weekday and not a holiday
      if (dayOfWeek !== 0 && dayOfWeek !== 6 && !holidayDates.includes(dateString)) {
        addedDays++;
      }
    }
    
    return result.toDate();
  }
  
  /**
   * Check if date is a working day
   * @param {Date|string|number} date - Date to check
   * @param {Array} holidays - Array of holiday dates
   * @returns {boolean} Is working day
   */
  isWorkingDay(date, holidays = []) {
    const m = moment(date);
    const dayOfWeek = m.day();
    const dateString = m.format('YYYY-MM-DD');
    const holidayDates = holidays.map(h => moment(h).format('YYYY-MM-DD'));
    
    return dayOfWeek !== 0 && dayOfWeek !== 6 && !holidayDates.includes(dateString);
  }
  
  /**
   * Parse date with multiple format support
   * @param {string} dateString - Date string to parse
   * @param {Array} formats - Array of possible formats
   * @returns {Date|null} Parsed date or null
   */
  parseDate(dateString, formats = null) {
    const defaultFormats = [
      'YYYY-MM-DD',
      'MM/DD/YYYY',
      'DD/MM/YYYY',
      'YYYY-MM-DD HH:mm:ss',
      'MM/DD/YYYY HH:mm:ss',
      'DD/MM/YYYY HH:mm:ss',
      'YYYY-MM-DDTHH:mm:ss.SSSZ',
      'YYYY-MM-DDTHH:mm:ssZ',
      moment.ISO_8601
    ];
    
    const formatsToTry = formats || defaultFormats;
    
    for (const format of formatsToTry) {
      const parsed = moment(dateString, format, true);
      if (parsed.isValid()) {
        return parsed.toDate();
      }
    }
    
    // Try without strict parsing as fallback
    const fallback = moment(dateString);
    return fallback.isValid() ? fallback.toDate() : null;
  }
  
  /**
   * Get calendar week number
   * @param {Date|string|number} date - Date to check
   * @returns {Object} Week information
   */
  getWeekInfo(date) {
    const m = moment(date);
    
    return {
      week: m.week(),
      isoWeek: m.isoWeek(),
      year: m.year(),
      startOfWeek: m.clone().startOf('week').toDate(),
      endOfWeek: m.clone().endOf('week').toDate()
    };
  }
  
  /**
   * Format date for different contexts
   */
  formatters = {
    short: (date) => this.format(date, 'MMM D, YYYY'),
    long: (date) => this.format(date, 'MMMM D, YYYY'),
    time: (date) => this.format(date, 'h:mm A'),
    datetime: (date) => this.format(date, 'MMM D, YYYY h:mm A'),
    iso: (date) => moment(date).toISOString(),
    relative: (date) => this.fromNow(date),
    monthYear: (date) => this.format(date, 'MMMM YYYY'),
    dayMonth: (date) => this.format(date, 'MMM D'),
    fullDate: (date) => this.format(date, 'dddd, MMMM D, YYYY'),
    
    // Context-specific formatters
    invoice: (date) => this.format(date, 'YYYY-MM-DD'),
    filename: (date) => this.format(date, 'YYYY-MM-DD-HHmmss'),
    log: (date) => this.format(date, 'YYYY-MM-DD HH:mm:ss.SSS'),
    api: (date) => moment(date).toISOString(),
    
    // Localized formatters
    localized: {
      short: (date, locale) => this.format(date, 'L', { locale }),
      long: (date, locale) => this.format(date, 'LL', { locale }),
      time: (date, locale) => this.format(date, 'LT', { locale }),
      datetime: (date, locale) => this.format(date, 'LLL', { locale })
    }
  };
  
  /**
   * Date validation utilities
   */
  validators = {
    isValid: (date) => moment(date).isValid(),
    isFuture: (date) => moment(date).isAfter(moment()),
    isPast: (date) => moment(date).isBefore(moment()),
    isToday: (date) => moment(date).isSame(moment(), 'day'),
    isThisWeek: (date) => moment(date).isSame(moment(), 'week'),
    isThisMonth: (date) => moment(date).isSame(moment(), 'month'),
    isThisYear: (date) => moment(date).isSame(moment(), 'year'),
    isBetween: (date, start, end) => moment(date).isBetween(start, end),
    isAfter: (date, compareDate) => moment(date).isAfter(compareDate),
    isBefore: (date, compareDate) => moment(date).isBefore(compareDate),
    isSameDay: (date1, date2) => moment(date1).isSame(date2, 'day')
  };
  
  /**
   * Date calculation utilities
   */
  calculations = {
    age: (birthDate) => moment().diff(moment(birthDate), 'years'),
    daysUntil: (date) => moment(date).diff(moment(), 'days'),
    daysSince: (date) => moment().diff(moment(date), 'days'),
    nextOccurrence: (dayOfWeek) => {
      const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
      const targetDay = days.indexOf(dayOfWeek.toLowerCase());
      const today = moment().day();
      const daysUntil = targetDay <= today ? targetDay + 7 - today : targetDay - today;
      return moment().add(daysUntil, 'days').toDate();
    }
  };
}

// Create singleton instance
const dateHelper = new DateHelper();

module.exports = dateHelper;