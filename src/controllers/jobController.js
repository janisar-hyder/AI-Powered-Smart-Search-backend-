// jobController.js - COMPLETE VERSION with history
const axios = require('axios');
const cheerio = require('cheerio');
const { v4: uuidv4 } = require('uuid');

// Initialize Supabase directly in this file
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Check if .env is loaded
console.log('Loading Supabase from .env:', {
  hasUrl: !!process.env.SUPABASE_URL,
  hasKey: !!process.env.SUPABASE_ANON_KEY
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: { persistSession: false }
  }
);

console.log('Supabase client created:', typeof supabase);

// Simple storage function
const storeFirstJobInHistory = async (job, query, country, city, userId = null) => {
  try {
    console.log('Starting to store job in history...');
    
    if (!job || !query) {
      console.error('Missing job or query');
      return null;
    }

    const jobHistoryData = {
      id: uuidv4(),
      user_id: userId || null,
      job_id: job.id || uuidv4(),
      title: job.title || 'No title',
      company: job.company || 'No company',
      location: job.location || 'No location',
      salary: job.salary || 'Not specified',
      job_type: job.jobType || 'Onsite',
      experience: job.experience || 'Not specified',
      description: job.description || 'No description',
      url: job.url || 'No URL',
      posted: job.posted || 'Recent',
      type: job.type || 'job',
      source: job.source || 'Unknown',
      query: query,
      country: country || null,
      city: city || null,
      created_at: new Date().toISOString()
    };

    console.log('Job data prepared:', {
      title: jobHistoryData.title,
      company: jobHistoryData.company
    });

    console.log('Attempting to insert into Supabase...');
    
    // Test Supabase connection first
    const testResponse = await supabase
      .from('job_history')
      .select('count', { count: 'exact', head: true });
    
    console.log('Supabase connection test:', testResponse.error ? 'Failed' : 'Success');
    
    // Insert the data
    const { data, error } = await supabase
      .from('job_history')
      .insert([jobHistoryData]);

    if (error) {
      console.error('❌ Supabase insert error:', error);
      console.error('Error code:', error.code);
      console.error('Error message:', error.message);
      console.error('Error details:', error.details);
      return null;
    }

    console.log('✅ Job stored successfully:', jobHistoryData.id);
    return jobHistoryData;

  } catch (error) {
    console.error('🚨 Fatal error in storeFirstJobInHistory:', error.message);
    console.error('Full error:', error);
    return null;
  }
};

// Get job history function
const getJobHistory = async (req, res) => {
  try {
    // Get pagination params from query string, not body
    const { limit = 50, offset = 0 } = req.query;
    
    if (!supabase) {
      return res.status(500).json({
        error: 'Database connection not available',
        success: false
      });
    }

    // 1. Extract Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'No authorization token provided',
        success: false
      });
    }

    const token = authHeader.replace('Bearer ', '');
    
    // 2. Get current user from token
    const { data: { user: currentUser }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError || !currentUser) {
      console.error('Auth error:', authError?.message || 'No user found');
      return res.status(401).json({
        error: 'Invalid or expired token',
        message: authError?.message || 'User not found',
        success: false
      });
    }

    console.log(`🔐 Fetching job history for authenticated user: ${currentUser.id}`);

    // 3. Query job_history for the authenticated user (no user_id needed in body)
    const { data, error, count } = await supabase
      .from('job_history')
      .select('*', { count: 'exact' })
      .eq('user_id', currentUser.id) // Automatically use ID from token
      .order('created_at', { ascending: false })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    if (error) {
      throw error;
    }

    res.status(200).json({
      success: true,
      data: data,
      count: count || data.length,
      limit: parseInt(limit),
      offset: parseInt(offset),
      user: {
        id: currentUser.id,
        email: currentUser.email
      }
    });

  } catch (error) {
    console.error('Error fetching job history:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message,
      success: false
    });
  }
};

// Rest of your existing scraper functions remain the same...
const SCRAPER_API_KEY = '9ec92d418a07c6daa500cdd7c7148a5e';
const SCRAPER_API_URL = 'http://api.scraperapi.com';

const fetchWithScraperAPI = async (url, options = {}) => {
  try {
    const params = new URLSearchParams({
      api_key: SCRAPER_API_KEY,
      url: url,
      render: 'false',
      country_code: 'us',
      device_type: 'desktop'
    });

    const response = await axios.get(`${SCRAPER_API_URL}?${params.toString()}`, {
      timeout: 15000,
      ...options
    });
    
    return response;
  } catch (error) {
    console.error('ScraperAPI error:', error.message);
    throw error;
  }
};

const SCRAPING_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1'
};

const processQueryWithNLP = async (query, country = '', city = '') => {
  try {
    let processedQuery = query.toLowerCase().trim();
    processedQuery = processedQuery.replace(/[^\w\s]/g, ' ');
    processedQuery = processedQuery.replace(/\s+/g, ' ');

    const quickEnhancements = {
      'teacher': 'instructor educator',
      'hotel': 'hospitality',
      'driver': 'delivery',
      'chef': 'cook kitchen',
      'programming': 'coding developer'
    };

    let enhancedQuery = processedQuery;
    for (const [key, value] of Object.entries(quickEnhancements)) {
      if (processedQuery.includes(key)) {
        enhancedQuery += ' ' + value;
        break;
      }
    }

    return {
      original: query,
      processed: processedQuery,
      enhanced: enhancedQuery,
      entities: {
        country: country.toLowerCase(),
        city: city.toLowerCase()
      }
    };
  } catch (error) {
    return {
      original: query,
      processed: query.toLowerCase(),
      enhanced: query.toLowerCase(),
      entities: {
        country: country.toLowerCase(),
        city: city.toLowerCase()
      }
    };
  }
};

const generateJobId = () => {
  return uuidv4();
};

const scrapeLinkedInJobsDirect = async (query, country = '', city = '') => {
  try {
    let location = '';
    if (city && country) {
      location = `${city}, ${country}`;
    } else if (city) {
      location = city;
    } else if (country) {
      location = country;
    }

    console.log(`🔍 LinkedIn: "${query}" in "${location}"`);

    const response = await axios.get(`https://www.linkedin.com/jobs-guest/jobs/api/seeMoreJobPostings/search`, {
      params: {
        keywords: query,
        location: location,
        start: 0,
        count: 50
      },
      headers: {
        ...SCRAPING_HEADERS,
        'x-requested-with': 'XMLHttpRequest',
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'referer': 'https://www.linkedin.com/jobs/'
      },
      timeout: 10000
    });

    const $ = cheerio.load(response.data);
    const results = [];

    $('li').slice(0, 35).each((i, element) => {
      const title = $(element).find('.base-search-card__title').text().trim();
      const company = $(element).find('.base-search-card__subtitle').text().trim();
      const location = $(element).find('.job-search-card__location').text().trim();
      const metadata = $(element).find('.job-search-card__metadata').text().trim();
      const url = $(element).find('.base-card__full-link').attr('href');
      
      if (title && company) {
        let jobType = 'Onsite';
        const locationText = location.toLowerCase();
        if (locationText.includes('remote')) jobType = 'Remote';
        else if (locationText.includes('hybrid')) jobType = 'Hybrid';

        results.push({
          id: generateJobId(),
          title,
          company,
          location,
          salary: metadata.includes('$') ? metadata : 'Salary not specified',
          jobType,
          experience: 'Not specified',
          description: `${title} at ${company} in ${location}`,
          url: url || `https://www.linkedin.com/jobs/search/?keywords=${encodeURIComponent(query)}`,
          posted: 'Recent',
          type: 'job',
          source: 'LinkedIn'
        });
      }
    });

    console.log(`✅ LinkedIn: ${results.length} jobs`);
    return results;
  } catch (error) {
    console.error('LinkedIn failed:', error.message);
    return [];
  }
};

const scrapeCareerBuilderJobs = async (query, country = '', city = '') => {
  try {
    let location = '';
    if (city && country) {
      location = `${city}, ${country}`;
    } else if (city) {
      location = city;
    } else if (country) {
      location = country;
    }

    const careerBuilderUrl = `https://www.careerbuilder.com/jobs?keywords=${encodeURIComponent(query)}&location=${encodeURIComponent(location)}`;
    
    console.log(`🔍 CareerBuilder: ${query}`);
    
    const response = await fetchWithScraperAPI(careerBuilderUrl);
    const $ = cheerio.load(response.data);
    const results = [];

    $('.data-results-content-parent').slice(0, 25).each((i, element) => {
      const title = $(element).find('.data-results-title').text().trim();
      const company = $(element).find('.data-details').eq(0).text().trim();
      const location = $(element).find('.data-details').eq(1).text().trim();
      const url = $(element).find('a').attr('href');
      
      if (title && company) {
        results.push({
          id: generateJobId(),
          title,
          company,
          location,
          salary: 'Salary not specified',
          jobType: 'Onsite',
          experience: 'Not specified',
          description: `${title} at ${company} in ${location}`,
          url: url ? `https://www.careerbuilder.com${url}` : careerBuilderUrl,
          posted: 'Recent',
          type: 'job',
          source: 'CareerBuilder'
        });
      }
    });

    console.log(`✅ CareerBuilder: ${results.length} jobs`);
    return results;
  } catch (error) {
    console.error('CareerBuilder failed:', error.message);
    return [];
  }
};

const mixResultsQuickly = (linkedInJobs, careerBuilderJobs) => {
  const allJobs = [...linkedInJobs, ...careerBuilderJobs];
  
  for (let i = allJobs.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [allJobs[i], allJobs[j]] = [allJobs[j], allJobs[i]];
  }
  
  return allJobs;
};

// Main search function
const searchJobs = async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { query, country, city, userId } = req.body;

    if (!query || query.trim().length === 0) {
      return res.status(400).json({
        error: 'Search query is required'
      });
    }

    const processedQuery = await processQueryWithNLP(query, country, city);
    
    console.log(`🎯 FAST Search: "${query}" in ${city ? city + ', ' : ''}${country || 'Worldwide'}`);

    const scrapingPromises = [
      scrapeLinkedInJobsDirect(processedQuery.enhanced, country, city),
      scrapeCareerBuilderJobs(processedQuery.enhanced, country, city)
    ];

    const scrapingResults = await Promise.allSettled(scrapingPromises);

    const [linkedInResults, careerBuilderResults] = scrapingResults.map(result => 
      result.status === 'fulfilled' ? result.value : []
    );

    const sourcesUsed = [];
    if (linkedInResults.length > 0) sourcesUsed.push(`LinkedIn (${linkedInResults.length})`);
    if (careerBuilderResults.length > 0) sourcesUsed.push(`CareerBuilder (${careerBuilderResults.length})`);

    const allMixedResults = mixResultsQuickly(linkedInResults, careerBuilderResults);

    const uniqueResults = [];
    const seen = new Set();
    
    for (const job of allMixedResults) {
      const key = `${job.title}-${job.company}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueResults.push(job);
      }
    }

    // Store the first job
    let storedJob = null;
    if (uniqueResults.length > 0) {
      const firstJob = uniqueResults[0];
      console.log(`📋 First job to store: ${firstJob.title} at ${firstJob.company}`);
      
      // Call the storage function
      storedJob = await storeFirstJobInHistory(firstJob, query, country, city, userId);
      
      if (storedJob) {
        console.log('✅ Job stored successfully in history');
      } else {
        console.log('⚠️ Job could not be stored in history');
      }
    }

    const executionTime = Date.now() - startTime;
    console.log(`⚡ Search completed in ${executionTime}ms`);

    if (uniqueResults.length === 0) {
      return res.status(404).json({
        success: false,
        error: `No job results found for "${query}"`,
        executionTime: `${executionTime}ms`,
        timestamp: new Date().toISOString(),
        storedInHistory: false
      });
    }

    res.status(200).json({
      success: true,
      originalQuery: query,
      country: country || 'Global',
      city: city || 'Multiple Locations',
      results: uniqueResults,
      totalResults: uniqueResults.length,
      sources: sourcesUsed,
      executionTime: `${executionTime}ms`,
      note: `Fast search completed in ${executionTime}ms - All ${uniqueResults.length} results displayed`,
      storedInHistory: !!storedJob,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    const executionTime = Date.now() - startTime;
    console.error(`💥 Search error after ${executionTime}ms:`, error);
    res.status(500).json({
      error: 'Internal server error during job search',
      message: error.message,
      executionTime: `${executionTime}ms`
    });
  }
};

module.exports = {
  searchJobs,
  getJobHistory
};