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
  console.log('✅ Supabase client initialized for university controller');
} else {
  console.error('❌ Missing Supabase environment variables');
  supabase = null;
}

// Create axios instance with proper SSL configuration
const axiosInstance = axios.create({
  timeout: 15000,
  httpsAgent: new https.Agent({  
    rejectUnauthorized: false
  })
});

// Function to store first university in history
const storeFirstUniversityInHistory = async (university, filters, userId = null) => {
  try {
    if (!university || !filters || !filters.country) {
      console.error('Missing required data for university history storage');
      return null;
    }

    if (!supabase) {
      console.error('Supabase client not initialized');
      return null;
    }

    // Create search query string
    const searchQuery = `${filters.field || 'all'} ${filters.studyLevel || 'all'} programs in ${filters.country}`;
    
    // Prepare data for Supabase
    const universityHistoryData = {
      id: uuidv4(),
      user_id: userId || null,
      university_name: university.title,
      location: university.location,
      country: filters.country,
      ranking: university.ranking,
      description: university.description,
      url: university.url,
      image: university.image,
      type: university.type || 'university',
      source: university.source,
      study_level: university.studyLevel,
      fields: university.fields || [],
      programs: university.programs || [],
      search_query: searchQuery,
      study_level_filter: filters.studyLevel || 'all',
      field_filter: filters.field || 'all',
      created_at: new Date().toISOString()
    };

    console.log('📝 Storing university in history:', {
      name: universityHistoryData.university_name,
      country: universityHistoryData.country,
      searchQuery: universityHistoryData.search_query
    });

    // Insert into Supabase
    const { data, error } = await supabase
      .from('university_history')
      .insert([universityHistoryData])
      .select();

    if (error) {
      console.error('❌ Error storing university in history:', error);
      console.error('Error details:', {
        code: error.code,
        message: error.message,
        details: error.details
      });
      return null;
    }

    console.log('✅ University stored in history:', {
      id: data[0]?.id,
      name: data[0]?.university_name,
      timestamp: data[0]?.created_at
    });
    
    return data?.[0] || null;
    
  } catch (error) {
    console.error('🚨 Error in storeFirstUniversityInHistory:', error.message);
    console.error('Stack trace:', error.stack);
    return null;
  }
};

// Enhanced headers to avoid detection
const getScrapingHeaders = () => {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0'
  ];
  
  return {
    'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
    'Referer': 'https://www.google.com/',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Sec-Fetch-User': '?1'
  };
};

// Map countries to their URL slugs for each platform
const platformCountrySlugs = {
  'unirank': {
    'poland': 'pl',
    'germany': 'de',
    'france': 'fr',
    'italy': 'it',
    'spain': 'es',
    'india': 'in',
    'pakistan': 'pk',
    'usa': 'us',
    'uk': 'uk',
    'canada': 'ca',
    'australia': 'au',
    'china': 'cn',
    'japan': 'jp',
    'brazil': 'br',
    'mexico': 'mx'
  },
  'wikipedia': {
    'poland': 'List_of_universities_in_Poland',
    'germany': 'List_of_universities_in_Germany',
    'france': 'List_of_universities_in_France',
    'italy': 'List_of_universities_in_Italy',
    'spain': 'List_of_universities_in_Spain',
    'india': 'List_of_universities_in_India',
    'pakistan': 'List_of_universities_in_Pakistan',
    'usa': 'List_of_universities_in_the_United_States',
    'uk': 'List_of_universities_in_the_United_Kingdom',
    'canada': 'List_of_universities_in_Canada',
    'australia': 'List_of_universities_in_Australia',
    'china': 'List_of_universities_in_China',
    'japan': 'List_of_universities_in_Japan',
    'brazil': 'List_of_universities_in_Brazil',
    'mexico': 'List_of_universities_in_Mexico'
  }
};

// Comprehensive university fields by category
const universityFields = {
  'engineering': [
    'Computer Engineering', 'Electrical Engineering', 'Mechanical Engineering', 
    'Civil Engineering', 'Chemical Engineering', 'Aerospace Engineering',
    'Biomedical Engineering', 'Environmental Engineering', 'Software Engineering'
  ],
  'computer_science': [
    'Computer Science', 'Information Technology', 'Data Science', 
    'Artificial Intelligence', 'Cybersecurity', 'Software Development',
    'Computer Networks', 'Database Systems', 'Web Development'
  ],
  'business': [
    'Business Administration', 'Finance', 'Marketing', 'Accounting',
    'Human Resources', 'International Business', 'Entrepreneurship',
    'Supply Chain Management', 'Economics'
  ],
  'medicine': [
    'Medicine', 'Dentistry', 'Pharmacy', 'Nursing', 
    'Public Health', 'Biomedical Sciences', 'Physiotherapy',
    'Veterinary Medicine', 'Medical Laboratory Sciences'
  ],
  'law': [
    'Law', 'Criminal Justice', 'International Law', 'Corporate Law',
    'Human Rights Law', 'Environmental Law', 'Intellectual Property Law'
  ],
  'arts': [
    'Fine Arts', 'Graphic Design', 'Music', 'Theater Arts',
    'Film Studies', 'Creative Writing', 'Art History',
    'Digital Arts', 'Photography'
  ],
  'sciences': [
    'Physics', 'Chemistry', 'Biology', 'Mathematics',
    'Environmental Science', 'Geology', 'Biotechnology',
    'Astronomy', 'Statistics'
  ],
  'social_sciences': [
    'Psychology', 'Sociology', 'Political Science', 'Anthropology',
    'International Relations', 'Social Work', 'Communication Studies'
  ],
  'education': [
    'Education', 'Early Childhood Education', 'Special Education',
    'Educational Leadership', 'Curriculum Development'
  ],
  'architecture': [
    'Architecture', 'Urban Planning', 'Interior Design',
    'Landscape Architecture', 'Construction Management'
  ]
};

// Study levels with proper naming
const studyLevels = {
  'bachelor': ['Bachelor of Arts', 'Bachelor of Science', 'Bachelor of Engineering', 'Bachelor of Business Administration'],
  'master': ['Master of Arts', 'Master of Science', 'Master of Engineering', 'Master of Business Administration'],
  'phd': ['PhD', 'Doctor of Philosophy', 'Research Doctorate'],
  'diploma': ['Diploma', 'Advanced Diploma', 'Graduate Diploma'],
  'certificate': ['Certificate', 'Professional Certificate', 'Graduate Certificate']
};

// Helper function to normalize input values
const normalizeInput = (value) => {
  if (!value || value.toLowerCase() === 'all' || value.toLowerCase() === 'all programs' || value.toLowerCase() === 'all fields') {
    return 'all';
  }
  return value.toLowerCase();
};

// Enhanced university data generator with dynamic handling
const generateUniversityData = (name, location, country, studyLevel, field) => {
  // Normalize inputs
  const normalizedStudyLevel = normalizeInput(studyLevel);
  const normalizedField = normalizeInput(field);
  
  // Determine fields based on input
  let selectedFields = [];
  
  if (normalizedField === 'all') {
    // Select 4-6 random fields from different categories
    const fieldCategories = Object.keys(universityFields);
    const shuffledCategories = fieldCategories.sort(() => 0.5 - Math.random()).slice(0, 4);
    
    shuffledCategories.forEach(category => {
      const fieldsInCategory = universityFields[category];
      const randomField = fieldsInCategory[Math.floor(Math.random() * fieldsInCategory.length)];
      if (!selectedFields.includes(randomField)) {
        selectedFields.push(randomField);
      }
    });
    
    // Add 1-2 more random fields
    const allFields = Object.values(universityFields).flat();
    while (selectedFields.length < 6) {
      const randomField = allFields[Math.floor(Math.random() * allFields.length)];
      if (!selectedFields.includes(randomField)) {
        selectedFields.push(randomField);
      }
    }
  } else {
    // For specific field search, include that field plus related ones
    const fieldLower = normalizedField;
    let mainCategory = 'engineering';
    
    // Find the category for the searched field
    for (const [category, fields] of Object.entries(universityFields)) {
      if (fields.some(f => f.toLowerCase().includes(fieldLower))) {
        mainCategory = category;
        break;
      }
    }
    
    // Include the searched field
    const matchingField = universityFields[mainCategory].find(f => 
      f.toLowerCase().includes(fieldLower)
    ) || field;
    
    selectedFields.push(matchingField);
    
    // Add related fields from the same category
    universityFields[mainCategory].forEach(f => {
      if (f !== matchingField && selectedFields.length < 4) {
        selectedFields.push(f);
      }
    });
    
    // Add some random fields from other categories
    const otherCategories = Object.keys(universityFields).filter(cat => cat !== mainCategory);
    otherCategories.sort(() => 0.5 - Math.random()).slice(0, 2).forEach(category => {
      const randomField = universityFields[category][Math.floor(Math.random() * universityFields[category].length)];
      if (!selectedFields.includes(randomField)) {
        selectedFields.push(randomField);
      }
    });
  }
  
  // Generate study levels dynamically
  let selectedStudyLevels = [];
  
  if (normalizedStudyLevel === 'all') {
    // Include all study levels
    selectedStudyLevels = ['Bachelor Programs', 'Master Programs', 'PhD Programs', 'Diploma Programs', 'Certificate Programs'];
  } else {
    // For specific study level
    const levelLower = normalizedStudyLevel;
    
    if (levelLower.includes('bachelor') || levelLower.includes('undergraduate')) {
      selectedStudyLevels = ['Bachelor Programs'];
    } else if (levelLower.includes('master') || levelLower.includes('graduate')) {
      selectedStudyLevels = ['Master Programs'];
    } else if (levelLower.includes('phd') || levelLower.includes('doctor')) {
      selectedStudyLevels = ['PhD Programs'];
    } else if (levelLower.includes('diploma')) {
      selectedStudyLevels = ['Diploma Programs'];
    } else if (levelLower.includes('certificate')) {
      selectedStudyLevels = ['Certificate Programs'];
    } else {
      // Default to all levels if unknown
      selectedStudyLevels = ['Bachelor Programs', 'Master Programs', 'PhD Programs'];
    }
  }
  
  // Generate programs based on both field and study level
  const programs = [];
  
  if (normalizedField === 'all' && normalizedStudyLevel === 'all') {
    // Both are 'all' - generate diverse programs across fields and levels
    selectedFields.slice(0, 5).forEach(fieldName => {
      selectedStudyLevels.slice(0, 2).forEach(level => {
        programs.push({
          name: fieldName,
          level: level,
          duration: getRandomDuration(fieldName, level),
          type: 'Full-time'
        });
      });
    });
  } else if (normalizedField === 'all') {
    // Field is 'all', study level is specific - generate programs in all fields for that level
    selectedFields.slice(0, 6).forEach(fieldName => {
      programs.push({
        name: fieldName,
        level: selectedStudyLevels[0],
        duration: getRandomDuration(fieldName, selectedStudyLevels[0]),
        type: 'Full-time'
      });
    });
  } else if (normalizedStudyLevel === 'all') {
    // Study level is 'all', field is specific - generate programs in that field for all levels
    selectedFields.slice(0, 4).forEach(fieldName => {
      selectedStudyLevels.slice(0, 3).forEach(level => {
        programs.push({
          name: fieldName,
          level: level,
          duration: getRandomDuration(fieldName, level),
          type: 'Full-time'
        });
      });
    });
  } else {
    // Both are specific
    selectedFields.slice(0, 4).forEach(fieldName => {
      programs.push({
        name: fieldName,
        level: selectedStudyLevels[0],
        duration: getRandomDuration(fieldName, selectedStudyLevels[0]),
        type: 'Full-time'
      });
    });
  }
  
  // Limit programs to reasonable number
  const finalPrograms = programs.slice(0, 8);
  
  // Generate description based on the combination
  let description = `${name} in ${location}, offering `;
  
  if (normalizedStudyLevel === 'all' && normalizedField === 'all') {
    description += `comprehensive programs across all study levels and fields including ${selectedFields.slice(0, 3).join(', ')}`;
  } else if (normalizedStudyLevel === 'all') {
    description += `programs at all study levels in ${field} and related fields`;
  } else if (normalizedField === 'all') {
    description += `${studyLevel} programs across various fields including ${selectedFields.slice(0, 3).join(', ')}`;
  } else {
    description += `${studyLevel} programs in ${field} and related fields`;
  }
  
  return {
    fields: selectedFields,
    studyLevels: selectedStudyLevels.join(', '),
    programs: finalPrograms,
    description: description
  };
};

// Enhanced duration generator that considers both field and level
const getRandomDuration = (fieldName, level) => {
  const levelLower = level.toLowerCase();
  
  if (levelLower.includes('phd') || levelLower.includes('doctor')) {
    return '3-5 years';
  } else if (levelLower.includes('master')) {
    return '1-2 years';
  } else if (levelLower.includes('bachelor')) {
    if (fieldName.toLowerCase().includes('medicine') || fieldName.toLowerCase().includes('architecture')) {
      return '5-6 years';
    }
    return '3-4 years';
  } else if (levelLower.includes('diploma')) {
    return '1-2 years';
  } else if (levelLower.includes('certificate')) {
    return '6 months - 1 year';
  } else {
    return '3-4 years';
  }
};

// 1. Scrape UniRank.org with improved parsing
const scrapeUniRank = async (filters) => {
  try {
    const { country, studyLevel = 'all', field = 'all' } = filters;
    const countrySlug = platformCountrySlugs.unirank[country.toLowerCase()] || country.toLowerCase();
    
    const url = `https://www.4icu.org/${countrySlug}/`;
    
    console.log(`Scraping UniRank: ${url}`);
    
    const response = await axiosInstance.get(url, {
      headers: getScrapingHeaders()
    });
    
    const $ = cheerio.load(response.data);
    const results = [];
    
    // Extract university data from ranking tables
    $('table tbody tr').each((i, element) => {
      if (i < 40) {
        const cells = $(element).find('td');
        if (cells.length >= 2) {
          const name = $(cells[1]).text().trim();
          const ranking = $(cells[0]).text().trim();
          const location = $(cells[2]).text().trim() || country;
          
          if (name && name.length > 3) {
            const universityData = generateUniversityData(name, location, country, studyLevel, field);
            
            results.push({
              title: name,
              location: location,
              ranking: ranking || 'Ranked',
              description: universityData.description,
              url: url,
              image: 'https://via.placeholder.com/200x200?text=University',
              type: 'university',
              source: 'UniRank',
              studyLevel: universityData.studyLevels,
              field: universityData.fields.join(', '),
              fields: universityData.fields,
              programs: universityData.programs
            });
          }
        }
      }
    });
    
    return results.length > 0 ? results : await scrapeUniRankFallback(filters);
  } catch (error) {
    console.error('UniRank scraping failed:', error.message);
    return await scrapeUniRankFallback(filters);
  }
};

// Fallback for UniRank
const scrapeUniRankFallback = async (filters) => {
  try {
    const { country, studyLevel = 'all', field = 'all' } = filters;
    const url = `https://www.unirank.org/search/?q=universities+in+${country}`;
    
    const response = await axiosInstance.get(url, {
      headers: getScrapingHeaders()
    });
    
    const $ = cheerio.load(response.data);
    const results = [];
    
    $('.result-item, .university-item, tr').each((i, element) => {
      if (i < 30) {
        const name = $(element).find('h3, h4, .title, a').first().text().trim();
        if (isValidUniversityName(name)) {
          const universityData = generateUniversityData(name, country, country, studyLevel, field);
          
          results.push({
            title: name,
            location: country,
            ranking: 'Listed',
            description: universityData.description,
            url: `https://www.unirank.org/search/?q=${encodeURIComponent(name)}`,
            image: 'https://via.placeholder.com/200x200?text=University',
            type: 'university',
            source: 'UniRank',
            studyLevel: universityData.studyLevels,
            field: universityData.fields.join(', '),
            fields: universityData.fields,
            programs: universityData.programs
          });
        }
      }
    });
    
    return results;
  } catch (error) {
    console.error('UniRank fallback also failed:', error.message);
    return [];
  }
};

// 2. Enhanced Wikipedia scraping
const scrapeWikipediaUniversities = async (filters) => {
  try {
    const { country, studyLevel = 'all', field = 'all' } = filters;
    
    const wikiPage = platformCountrySlugs.wikipedia[country.toLowerCase()] || 'List_of_universities_and_colleges_by_country';
    const url = `https://en.wikipedia.org/wiki/${wikiPage}`;
    
    console.log(`Scraping Wikipedia: ${url}`);
    
    const response = await axiosInstance.get(url, {
      headers: getScrapingHeaders()
    });
    
    const $ = cheerio.load(response.data);
    const results = [];
    
    // Multiple selectors for different Wikipedia table structures
    const tableSelectors = [
      '.wikitable tbody tr',
      'table.wikitable tbody tr',
      '.sortable tbody tr'
    ];
    
    let universitiesFound = 0;
    
    for (const selector of tableSelectors) {
      $(selector).each((i, element) => {
        if (universitiesFound >= 35) return false;
        
        const cells = $(element).find('td');
        if (cells.length >= 2) {
          const nameLink = $(cells[0]).find('a');
          const name = nameLink.text().trim() || $(cells[0]).text().trim();
          const location = $(cells[1]).text().trim() || country;
          
          if (isValidUniversityName(name) && universitiesFound < 35) {
            const universityData = generateUniversityData(name, location, country, studyLevel, field);
            
            results.push({
              title: cleanUniversityName(name),
              location: cleanLocation(location),
              ranking: 'Wikipedia Listed',
              description: universityData.description,
              url: nameLink.attr('href') ? `https://en.wikipedia.org${nameLink.attr('href')}` : `https://en.wikipedia.org/wiki/${encodeURIComponent(name.replace(/\s+/g, '_'))}`,
              image: 'https://via.placeholder.com/200x200?text=University',
              type: 'university',
              source: 'Wikipedia',
              studyLevel: universityData.studyLevels,
              field: universityData.fields.join(', '),
              fields: universityData.fields,
              programs: universityData.programs
            });
            
            universitiesFound++;
          }
        }
      });
      
      if (universitiesFound > 0) break;
    }
    
    return results;
  } catch (error) {
    console.error('Wikipedia scraping failed:', error.message);
    return [];
  }
};

// 3. Scrape University Directories with better error handling
const scrapeUniversityDirectories = async (filters) => {
  try {
    const { country, studyLevel = 'all', field = 'all' } = filters;
    
    const directories = [
      {
        name: 'University Directory',
        url: `https://www.university-directory.eu/${country.toLowerCase()}/${country.toLowerCase()}-universities.html`
      },
      {
        name: 'World University Directory',
        url: `https://www.webometrics.info/en/${country.toLowerCase()}`,
        fallback: `https://www.webometrics.info/en/search/${country}%20universities`
      }
    ];
    
    const scrapingPromises = directories.map(dir => scrapeDirectory(dir, filters));
    const results = await Promise.allSettled(scrapingPromises);
    
    let allResults = [];
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        allResults = [...allResults, ...result.value];
      }
    });
    
    return allResults;
  } catch (error) {
    console.error('University directories scraping failed:', error.message);
    return [];
  }
};

// Helper function for directory scraping
const scrapeDirectory = async (directory, filters) => {
  try {
    const { country, studyLevel = 'all', field = 'all' } = filters;
    
    const response = await axiosInstance.get(directory.url, {
      headers: getScrapingHeaders(),
      timeout: 10000
    });
    
    const $ = cheerio.load(response.data);
    const results = [];
    
    $('.university-item, .listing-item, tr, li').each((i, element) => {
      if (i < 25) {
        const name = $(element).find('h3, h4, .title, a').first().text().trim();
        if (isValidUniversityName(name)) {
          const universityData = generateUniversityData(name, country, country, studyLevel, field);
          
          results.push({
            title: cleanUniversityName(name),
            location: country,
            ranking: `${directory.name} Listed`,
            description: universityData.description,
            url: directory.url,
            image: 'https://via.placeholder.com/200x200?text=University',
            type: 'university',
            source: directory.name,
            studyLevel: universityData.studyLevels,
            field: universityData.fields.join(', '),
            fields: universityData.fields,
            programs: universityData.programs
          });
        }
      }
    });
    
    return results;
  } catch (error) {
    console.error(`${directory.name} scraping failed:`, error.message);
    return [];
  }
};

// Helper functions
const isValidUniversityName = (name) => {
  if (!name || name.length < 3) return false;
  const invalidKeywords = ['list', 'total', 'ranking', '...', 'etc.', 'university of the', 'college of the'];
  return !invalidKeywords.some(keyword => name.toLowerCase().includes(keyword));
};

const cleanUniversityName = (name) => {
  return name.replace(/\[.*?\]/g, '').replace(/\(.*?\)/g, '').trim();
};

const cleanLocation = (location) => {
  return location.split('\n')[0].split('[')[0].trim();
};

// Main function to scrape all sources in parallel
const scrapeAllUniversitySources = async (filters) => {
  try {
    console.log(`Starting university search with filters`, filters);
    
    // Run all scrapers in parallel with timeout
    const scrapingPromises = [
      scrapeUniRank(filters),
      scrapeWikipediaUniversities(filters),
      scrapeUniversityDirectories(filters)
    ].map(promise => 
      Promise.race([
        promise,
        new Promise((resolve) => setTimeout(() => resolve([]), 15000))
      ])
    );

    const results = await Promise.allSettled(scrapingPromises);
    
    let allUniversities = [];
    const sources = ['UniRank', 'Wikipedia', 'University Directories'];
    
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value && result.value.length > 0) {
        allUniversities = [...allUniversities, ...result.value];
        console.log(`${sources[index]} returned ${result.value.length} universities`);
      } else {
        console.log(`${sources[index]} returned 0 universities`);
      }
    });

    // Deduplicate results
    const uniqueUniversities = [];
    const seenTitles = new Set();
    
    for (const university of allUniversities) {
      const normalizedTitle = university.title.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (!seenTitles.has(normalizedTitle) && university.title.length > 3) {
        seenTitles.add(normalizedTitle);
        uniqueUniversities.push(university);
      }
    }

    return uniqueUniversities.slice(0, 50);
  } catch (error) {
    console.error('Error in multi-source scraping:', error);
    return [];
  }
};

// Main search function - Dynamic and handles partial inputs
const searchUniversityPrograms = async (req, res) => {
  try {
    const { country, studyLevel, field, userId } = req.body;

    if (!country) {
      return res.status(400).json({
        error: 'Country is required'
      });
    }

    // Set default values if not provided
    const filters = {
      country: country,
      studyLevel: studyLevel || 'all',
      field: field || 'all'
    };

    console.log(`Searching universities with filters:`, filters);

    const searchResults = await scrapeAllUniversitySources(filters);

    // Store first university in history
    let storedUniversity = null;
    if (searchResults.length > 0) {
      const firstUniversity = searchResults[0];
      console.log(`📋 First university to store: ${firstUniversity.title} in ${firstUniversity.location}`);
      
      storedUniversity = await storeFirstUniversityInHistory(firstUniversity, filters, userId);
      
      if (storedUniversity) {
        console.log('✅ University stored successfully in history');
      } else {
        console.log('⚠️ University could not be stored in history');
      }
    }

    res.status(200).json({
      success: true,
      filters: filters,
      results: searchResults,
      totalResults: searchResults.length,
      storedInHistory: !!storedUniversity,
      storedUniversity: storedUniversity ? {
        id: storedUniversity.id,
        name: storedUniversity.university_name,
        location: storedUniversity.location,
        timestamp: storedUniversity.created_at
      } : null,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('University programs search error:', error);
    res.status(500).json({
      error: 'Internal server error during university search',
      message: error.message,
      success: false
    });
  }
};

// Function to get university search history
// Function to get university search history - SECURE VERSION
const getUniversityHistory = async (req, res) => {
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

    console.log(`🔐 Fetching university history for user: ${user.id}`);

    // 3. Query university_history filtered by user_id
    const { data, error, count } = await supabase
      .from('university_history')
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
    console.error('Error fetching university history:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message,
      success: false
    });
  }
};

module.exports = {
  searchUniversityPrograms,
  getUniversityHistory
};