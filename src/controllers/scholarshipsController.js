const axios = require('axios');
const cheerio = require('cheerio');
const https = require('https');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

let supabase;
if (supabaseUrl && supabaseKey) {
  supabase = createClient(supabaseUrl, supabaseKey, {
    auth: { persistSession: false }
  });
  console.log('✅ Supabase client initialized for scholarship controller');
} else {
  console.error('❌ Missing Supabase environment variables');
  supabase = null;
}

// Function to store first scholarship in history
const storeFirstScholarshipInHistory = async (scholarship, filters, userId = null) => {
  try {
    if (!scholarship || !filters || !filters.country) {
      console.error('Missing required data for scholarship history storage');
      return null;
    }

    if (!supabase) {
      console.error('Supabase client not initialized');
      return null;
    }

    // Create search query string
    const searchQuery = `${filters.field} ${filters.studyLevel} scholarships in ${filters.country}`;
    
    // Prepare data for Supabase
    const scholarshipHistoryData = {
      id: uuidv4(),
      user_id: userId || null,
      scholarship_title: scholarship.title,
      location: scholarship.location,
      country: filters.country,
      ranking: scholarship.ranking,
      description: scholarship.description,
      url: scholarship.url,
      image: scholarship.image,
      type: scholarship.type || 'scholarship',
      source: scholarship.source,
      study_level: scholarship.studyLevel,
      field: scholarship.field,
      fields: scholarship.fields || [],
      programs: scholarship.programs || [],
      amount: scholarship.amount,
      sponsor: scholarship.sponsor,
      deadline: scholarship.deadline,
      search_query: searchQuery,
      study_level_filter: filters.studyLevel,
      field_filter: filters.field,
      created_at: new Date().toISOString()
    };

    console.log('📝 Storing scholarship in history:', {
      title: scholarshipHistoryData.scholarship_title,
      country: scholarshipHistoryData.country,
      source: scholarshipHistoryData.source
    });

    // Insert into Supabase
    const { data, error } = await supabase
      .from('scholarship_history')
      .insert([scholarshipHistoryData])
      .select();

    if (error) {
      console.error('❌ Error storing scholarship in history:', error);
      console.error('Error details:', {
        code: error.code,
        message: error.message,
        details: error.details
      });
      return null;
    }

    console.log('✅ Scholarship stored in history:', {
      id: data[0]?.id,
      title: data[0]?.scholarship_title,
      timestamp: data[0]?.created_at
    });
    
    return data?.[0] || null;
    
  } catch (error) {
    console.error('🚨 Error in storeFirstScholarshipInHistory:', error.message);
    console.error('Stack trace:', error.stack);
    return null;
  }
};

// Create axios instance that ignores SSL errors
const axiosInstance = axios.create({
  httpsAgent: new https.Agent({  
    rejectUnauthorized: false
  }),
  timeout: 30000
});

const getScrapingHeaders = () => {
  return {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
    'Referer': 'https://www.google.com/'
  };
};

// Add delay to avoid rate limiting
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Extract study level from title
const extractStudyLevel = (title) => {
  const lowerTitle = title.toLowerCase();
  if (lowerTitle.includes('phd') || lowerTitle.includes('doctoral') || lowerTitle.includes('doctorate')) {
    return 'PhD Programs';
  } else if (lowerTitle.includes('master') || lowerTitle.includes('msc') || lowerTitle.includes('m.s')) {
    return 'Masters Programs';
  } else if (lowerTitle.includes('bachelor') || lowerTitle.includes('undergraduate')) {
    return 'Undergraduate Programs';
  } else if (lowerTitle.includes('postdoc')) {
    return 'Postdoctoral Programs';
  }
  return 'Various Programs';
};

// Extract field of study from title
const extractField = (title) => {
  const lowerTitle = title.toLowerCase();
  if (lowerTitle.includes('computer') || lowerTitle.includes('computing') || lowerTitle.includes('software') || lowerTitle.includes('it ') || lowerTitle.includes('information technology')) {
    return 'Computer Science';
  } else if (lowerTitle.includes('business') || lowerTitle.includes('management') || lowerTitle.includes('mba') || lowerTitle.includes('finance')) {
    return 'Business';
  } else if (lowerTitle.includes('engineering')) {
    return 'Engineering';
  } else if (lowerTitle.includes('medicine') || lowerTitle.includes('medical') || lowerTitle.includes('health')) {
    return 'Medicine';
  } else if (lowerTitle.includes('arts') || lowerTitle.includes('humanities')) {
    return 'Arts';
  } else if (lowerTitle.includes('science') || lowerTitle.includes('physics') || lowerTitle.includes('chemistry') || lowerTitle.includes('biology')) {
    return 'Science';
  } else if (lowerTitle.includes('environmental') || lowerTitle.includes('ecology')) {
    return 'Environmental Science';
  } else if (lowerTitle.includes('law') || lowerTitle.includes('legal')) {
    return 'Human Rights Law';
  } else if (lowerTitle.includes('aerospace') || lowerTitle.includes('aviation')) {
    return 'Aerospace Engineering';
  } else if (lowerTitle.includes('music')) {
    return 'Music';
  } else if (lowerTitle.includes('web') || lowerTitle.includes('development')) {
    return 'Web Development';
  } else if (lowerTitle.includes('film') || lowerTitle.includes('cinema')) {
    return 'Film Studies';
  }
  return 'Various Fields';
};

// Extract fields array from title and content
const extractFields = (title, content) => {
  const fields = new Set();
  const lowerTitle = title.toLowerCase();
  const lowerContent = content.toLowerCase();
  
  // Check for multiple fields
  const fieldMappings = [
    { keywords: ['computer', 'computing', 'software', 'it ', 'information technology'], field: 'Computer Science' },
    { keywords: ['business', 'management', 'mba', 'finance'], field: 'Business' },
    { keywords: ['engineering'], field: 'Engineering' },
    { keywords: ['medicine', 'medical', 'health'], field: 'Medicine' },
    { keywords: ['arts', 'humanities'], field: 'Arts' },
    { keywords: ['science', 'physics', 'chemistry', 'biology'], field: 'Science' },
    { keywords: ['environmental', 'ecology'], field: 'Environmental Science' },
    { keywords: ['law', 'legal', 'human rights'], field: 'Human Rights Law' },
    { keywords: ['aerospace', 'aviation'], field: 'Aerospace Engineering' },
    { keywords: ['music'], field: 'Music' },
    { keywords: ['web', 'development'], field: 'Web Development' },
    { keywords: ['film', 'cinema'], field: 'Film Studies' }
  ];
  
  fieldMappings.forEach(({ keywords, field }) => {
    if (keywords.some(keyword => lowerTitle.includes(keyword) || lowerContent.includes(keyword))) {
      fields.add(field);
    }
  });
  
  return fields.size > 0 ? Array.from(fields) : ['Various Fields'];
};

// Extract amount from content
const extractAmount = (content) => {
  const amountMatches = content.match(/\$?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)/g);
  if (amountMatches && amountMatches.length > 0) {
    const amounts = amountMatches.map(amt => amt.replace(/,/g, ''));
    const numericAmounts = amounts.map(amt => parseFloat(amt.replace(/[^\d.]/g, ''))).filter(amt => !isNaN(amt));
    if (numericAmounts.length > 0) {
      const maxAmount = Math.max(...numericAmounts);
      return `$${maxAmount.toLocaleString()}`;
    }
  }
  return 'Varies';
};

// Extract duration from content
const extractDuration = (content) => {
  const durationMatches = content.match(/(\d+)\s*(?:year|yr|month|semester)/i);
  if (durationMatches) {
    return `${durationMatches[1]} years`;
  }
  return '1-2 years';
};

// Extract country and location from content
const extractLocation = (content) => {
  let country = 'International';
  let city = '';
  
  const contentLower = content.toLowerCase();
  
  // Extract country
  const countryMappings = [
    { keywords: ['germany', 'german'], country: 'Germany' },
    { keywords: ['usa', 'united states', 'us ', 'america'], country: 'USA' },
    { keywords: ['uk', 'united kingdom', 'britain', 'england'], country: 'UK' },
    { keywords: ['canada', 'canadian'], country: 'Canada' },
    { keywords: ['australia', 'australian'], country: 'Australia' },
    { keywords: ['france', 'french'], country: 'France' },
    { keywords: ['netherlands', 'dutch'], country: 'Netherlands' },
    { keywords: ['sweden', 'swedish'], country: 'Sweden' },
    { keywords: ['switzerland', 'swiss'], country: 'Switzerland' },
    { keywords: ['austria', 'austrian'], country: 'Austria' },
    { keywords: ['pakistan', 'pakistani'], country: 'Pakistan' },
    { keywords: ['india', 'indian'], country: 'India' }
  ];
  
  for (const { keywords, country: countryName } of countryMappings) {
    if (keywords.some(keyword => contentLower.includes(keyword))) {
      country = countryName;
      break;
    }
  }
  
  // Extract city
  const cityPatterns = [
    'berlin', 'munich', 'london', 'paris', 'new york', 'toronto', 
    'sydney', 'amsterdam', 'stockholm', 'zurich', 'munich', 'frankfurt',
    'boston', 'cambridge', 'stanford', 'california'
  ];
  
  for (const pattern of cityPatterns) {
    if (contentLower.includes(pattern)) {
      city = pattern.charAt(0).toUpperCase() + pattern.slice(1);
      break;
    }
  }
  
  return { country, city };
};

// 1. ScholarshipDB.net - Extract results
const scrapeScholarshipDB = async (country, studyLevel, field) => {
  try {
    console.log(`Scraping ScholarshipDB.net for: ${country}, ${studyLevel}, ${field}`);
    
    const results = [];
    const baseUrl = 'https://www.scholarshipdb.net';
    
    // Build search query based on parameters
    let searchQuery = '';
    if (field !== 'all') {
      searchQuery = `${field} ${studyLevel}`;
    } else {
      searchQuery = `${studyLevel}`;
    }
    
    const maxPages = 2;
    
    for (let page = 1; page <= maxPages; page++) {
      try {
        await delay(500);
        
        const url = page === 1 
          ? `${baseUrl}/scholarships/${encodeURIComponent(searchQuery)}` 
          : `${baseUrl}/scholarships/${encodeURIComponent(searchQuery)}?page=${page}`;
        
        const { data } = await axiosInstance.get(url, {
          headers: getScrapingHeaders()
        });

        const $ = cheerio.load(data);
        
        $('ul.list-unstyled li, .scholarship-item, .item, .card, .listing').each((i, element) => {
          try {
            const titleElem = $(element).find('h4 a, h3 a, h2 a, .title a');
            const title = titleElem.text().trim();
            const url = titleElem.attr('href');
            
            if (title && title.length > 10) {
              const content = $(element).text();
              const { country: extractedCountry, city } = extractLocation(content);
              const studyLevel = extractStudyLevel(title);
              const primaryField = extractField(title);
              const fields = extractFields(title, content);
              const amount = extractAmount(content);
              const duration = extractDuration(content);
              
              let sponsor = $(element).find('a[href*="/scholarships-at-"]').text().trim() || 
                           $(element).find('.text-success').first().text().trim() ||
                           'Various Sponsors';
              
              const fullUrl = url && url.startsWith('http') ? url : `${baseUrl}${url || ''}`;
              
              // Filter by country if specified
              if (country !== 'all' && extractedCountry.toLowerCase() !== country.toLowerCase()) {
                return;
              }
              
              // Filter by field if specified
              if (field !== 'all' && !fields.some(f => f.toLowerCase().includes(field.toLowerCase()))) {
                return;
              }
              
              results.push({
                title: title.substring(0, 200),
                location: city || extractedCountry,
                ranking: (results.length + 1).toString(),
                description: `${title} scholarship for ${studyLevel} in ${primaryField}. ${sponsor} offers this funding opportunity for international students.`,
                url: fullUrl,
                image: "https://via.placeholder.com/200x200?text=Scholarship",
                type: "scholarship",
                source: "ScholarshipDB.net",
                studyLevel: studyLevel,
                field: fields.join(', '),
                fields: fields,
                programs: [
                  {
                    name: primaryField,
                    level: studyLevel,
                    duration: duration,
                    type: "Full-time"
                  }
                ],
                amount: amount,
                sponsor: sponsor,
                deadline: "Varies"
              });
            }
          } catch (error) {
            // Silent error for individual items
          }
        });
        
        const nextPageExists = $('.pagination a[rel="next"]').length > 0;
        if (!nextPageExists) break;
        
      } catch (error) {
        console.log(`ScholarshipDB.net page ${page} failed: ${error.message}`);
        break;
      }
    }

    console.log(`Found ${results.length} scholarships from ScholarshipDB.net`);
    return results;

  } catch (error) {
    console.error('ScholarshipDB.net failed:', error.message);
    return [];
  }
};

// 2. Scholars4Dev - Extract results
const scrapeScholars4Dev = async (country, studyLevel, field) => {
  try {
    console.log(`Scraping Scholars4Dev for: ${country}, ${studyLevel}, ${field}`);
    
    const results = [];
    const baseUrl = 'https://www.scholars4dev.com';
    
    const categories = [
      'category/field-of-study/information-technology-scholarships',
      'category/field-of-study/science-technology-scholarships',
      'category/field-of-study/engineering-scholarships',
      'category/field-of-study/business-scholarships'
    ];
    
    for (const category of categories) {
      try {
        await delay(500);
        
        const url = `${baseUrl}/${category}/`;
        const { data } = await axiosInstance.get(url, {
          headers: getScrapingHeaders()
        });

        const $ = cheerio.load(data);
        
        $('.post, article, .entry, .scholarship-item').each((i, element) => {
          try {
            const titleElem = $(element).find('h2 a, h3 a, .entry-title a');
            const title = titleElem.text().trim();
            const url = titleElem.attr('href');
            
            if (title && title.length > 10) {
              const content = $(element).text();
              const { country: extractedCountry, city } = extractLocation(content);
              const studyLevel = extractStudyLevel(title);
              const primaryField = extractField(title);
              const fields = extractFields(title, content);
              const amount = extractAmount(content);
              const duration = extractDuration(content);
              
              let sponsor = $(element).find('.post-meta, .byline').text().trim() || 'Scholars4Dev';
              
              const fullUrl = url && url.startsWith('http') ? url : `${baseUrl}${url || ''}`;
              
              // Filter by country if specified
              if (country !== 'all' && extractedCountry.toLowerCase() !== country.toLowerCase()) {
                return;
              }
              
              // Filter by field if specified
              if (field !== 'all' && !fields.some(f => f.toLowerCase().includes(field.toLowerCase()))) {
                return;
              }
              
              results.push({
                title: title.substring(0, 200),
                location: city || extractedCountry,
                ranking: (results.length + 1).toString(),
                description: `${title} scholarship for ${studyLevel} in ${primaryField}. ${sponsor} offers this funding opportunity for international students.`,
                url: fullUrl,
                image: "https://via.placeholder.com/200x200?text=Scholarship",
                type: "scholarship",
                source: "Scholars4Dev",
                studyLevel: studyLevel,
                field: fields.join(', '),
                fields: fields,
                programs: [
                  {
                    name: primaryField,
                    level: studyLevel,
                    duration: duration,
                    type: "Full-time"
                  }
                ],
                amount: amount,
                sponsor: sponsor,
                deadline: "Varies"
              });
            }
          } catch (error) {
            // Silent error for individual items
          }
        });
        
      } catch (error) {
        console.log(`Scholars4Dev category "${category}" failed: ${error.message}`);
      }
    }

    console.log(`Found ${results.length} scholarships from Scholars4Dev`);
    return results;

  } catch (error) {
    console.error('Scholars4Dev failed:', error.message);
    return [];
  }
};

// 3. Scholarship Positions - Extract results
const scrapeScholarshipPositions = async (country, studyLevel, field) => {
  try {
    console.log(`Scraping Scholarship Positions for: ${country}, ${studyLevel}, ${field}`);
    
    const results = [];
    const baseUrl = 'https://scholarship-positions.com';
    
    let searchQuery = '';
    if (field !== 'all') {
      searchQuery = `${field} ${studyLevel}`;
    } else {
      searchQuery = `${studyLevel}`;
    }
    
    const maxPages = 2;
    
    for (let page = 1; page <= maxPages; page++) {
      try {
        await delay(500);
        
        const url = `${baseUrl}/blog/page/${page}/?s=${encodeURIComponent(searchQuery)}`;
        const { data } = await axiosInstance.get(url, {
          headers: getScrapingHeaders()
        });

        const $ = cheerio.load(data);
        
        $('article, .post, .td_module_wrap').each((i, element) => {
          try {
            const titleElem = $(element).find('.entry-title a, h2 a, h3 a');
            const title = titleElem.text().trim();
            const url = titleElem.attr('href');
            
            if (title && url && title.length > 10) {
              const content = $(element).text();
              const { country: extractedCountry, city } = extractLocation(content);
              const studyLevel = extractStudyLevel(title);
              const primaryField = extractField(title);
              const fields = extractFields(title, content);
              const amount = extractAmount(content);
              const duration = extractDuration(content);
              
              let sponsor = $(element).find('.post-author, .author').text().trim() || 'Scholarship Positions';
              
              const fullUrl = url.startsWith('http') ? url : `${baseUrl}${url}`;
              
              // Filter by country if specified
              if (country !== 'all' && extractedCountry.toLowerCase() !== country.toLowerCase()) {
                return;
              }
              
              // Filter by field if specified
              if (field !== 'all' && !fields.some(f => f.toLowerCase().includes(field.toLowerCase()))) {
                return;
              }
              
              results.push({
                title: title.substring(0, 200),
                location: city || extractedCountry,
                ranking: (results.length + 1).toString(),
                description: `${title} scholarship for ${studyLevel} in ${primaryField}. ${sponsor} offers this funding opportunity for international students.`,
                url: fullUrl,
                image: "https://via.placeholder.com/200x200?text=Scholarship",
                type: "scholarship",
                source: "Scholarship Positions",
                studyLevel: studyLevel,
                field: fields.join(', '),
                fields: fields,
                programs: [
                  {
                    name: primaryField,
                    level: studyLevel,
                    duration: duration,
                    type: "Full-time"
                  }
                ],
                amount: amount,
                sponsor: sponsor,
                deadline: "Varies"
              });
            }
          } catch (error) {
            // Silent error for individual items
          }
        });
        
        const nextPageExists = $('.next.page-numbers, .pagination-next').length > 0;
        if (!nextPageExists) break;
        
      } catch (error) {
        console.log(`Scholarship Positions page ${page} failed: ${error.message}`);
        break;
      }
    }

    console.log(`Found ${results.length} scholarships from Scholarship Positions`);
    return results;

  } catch (error) {
    console.error('Scholarship Positions failed:', error.message);
    return [];
  }
};

// Main scraping function
const scrapeScholarshipsFromMultipleSources = async (country, studyLevel, field) => {
  console.log(`\n=== Starting scholarship search for: ${country}, ${studyLevel}, ${field} ===\n`);
  
  // Run all scrapers in parallel
  const scrapingPromises = [
    scrapeScholarshipDB(country, studyLevel, field),
    scrapeScholars4Dev(country, studyLevel, field),
    scrapeScholarshipPositions(country, studyLevel, field)
  ];

  try {
    const results = await Promise.allSettled(scrapingPromises);
    
    let allScholarships = [];
    
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value.length > 0) {
        allScholarships = [...allScholarships, ...result.value];
        console.log(`Source ${index + 1} returned ${result.value.length} scholarships`);
      } else {
        console.log(`Source ${index + 1} returned 0 scholarships`);
      }
    });

    console.log(`Total scholarships before deduplication: ${allScholarships.length}`);
    
    // Deduplication
    const uniqueScholarships = [];
    const seenUrls = new Set();
    
    for (const scholarship of allScholarships) {
      try {
        let normalizedUrl = '';
        if (scholarship.url) {
          try {
            const urlObj = new URL(scholarship.url);
            normalizedUrl = `${urlObj.hostname}${urlObj.pathname}`.toLowerCase();
          } catch (e) {
            normalizedUrl = scholarship.url.toLowerCase();
          }
        }
        
        if (!seenUrls.has(normalizedUrl)) {
          seenUrls.add(normalizedUrl);
          uniqueScholarships.push(scholarship);
        }
      } catch (error) {
        uniqueScholarships.push(scholarship);
      }
    }

    // Limit results
    const finalResults = uniqueScholarships.slice(0, 40);
    
    console.log(`\n=== Final unique scholarship count: ${finalResults.length} ===\n`);
    
    return finalResults;

  } catch (error) {
    console.error('Error in multi-source scraping:', error);
    return [];
  }
};

// Main search function with Supabase storage
const searchScholarships = async (req, res) => {
  try {
    const { country, studyLevel, field, userId } = req.body;

    if (!country || !studyLevel || !field) {
      return res.status(400).json({
        error: 'Country, studyLevel, and field are required'
      });
    }

    console.log(`Searching scholarships with filters:`, { country, studyLevel, field });

    const searchResults = await scrapeScholarshipsFromMultipleSources(country, studyLevel, field);

    // Store first scholarship in history
    let storedScholarship = null;
    if (searchResults.length > 0) {
      const firstScholarship = searchResults[0];
      console.log(`📋 First scholarship to store: ${firstScholarship.title} in ${firstScholarship.location}`);
      
      storedScholarship = await storeFirstScholarshipInHistory(firstScholarship, { country, studyLevel, field }, userId);
      
      if (storedScholarship) {
        console.log('✅ Scholarship stored successfully in history');
      } else {
        console.log('⚠️ Scholarship could not be stored in history');
      }
    }

    res.status(200).json({
      success: true,
      filters: {
        country,
        studyLevel,
        field
      },
      results: searchResults,
      totalResults: searchResults.length,
      storedInHistory: !!storedScholarship,
      storedScholarship: storedScholarship ? {
        id: storedScholarship.id,
        title: storedScholarship.scholarship_title,
        location: storedScholarship.location,
        source: storedScholarship.source,
        timestamp: storedScholarship.created_at
      } : null,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Scholarships search error:', error);
    res.status(500).json({
      error: 'Internal server error during scholarship search',
      message: error.message,
      success: false
    });
  }
};

// Function to get scholarship search history
// Function to get scholarship search history - SECURE VERSION
const getScholarshipHistory = async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;
    
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
    
    // 2. Get user from token using Supabase auth
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError) {
      console.error('Auth error:', authError.message);
      return res.status(401).json({
        error: 'Invalid or expired token',
        message: authError.message,
        success: false
      });
    }

    if (!user) {
      return res.status(401).json({
        error: 'User not found',
        success: false
      });
    }

    console.log(`🔐 Fetching scholarship history for user: ${user.id}`);

    // 3. Query scholarship_history filtered by user_id
    const { data, error, count } = await supabase
      .from('scholarship_history')
      .select('*', { count: 'exact' })
      .eq('user_id', user.id) // Only show this user's history
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

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
        id: user.id,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Error fetching scholarship history:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message,
      success: false
    });
  }
};

module.exports = {
  searchScholarships,
  getScholarshipHistory
};