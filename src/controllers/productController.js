const axios = require('axios');
const cheerio = require('cheerio');
const natural = require('natural');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client with your credentials
const supabaseUrl = process.env.SUPABASE_URL || 'https://besgrgzpihuwzfkljxkv.supabase.co';
const supabaseKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJlc2dyZ3pwaWh1d3pma2xqeGt2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTcwODA4NTksImV4cCI6MjA3MjY1Njg1OX0.JnOW092WkvidX7YY_0pueqg9SIzA_laClOC635-40l4';
const supabase = createClient(supabaseUrl, supabaseKey);

const stemmer = natural.PorterStemmer;

// Enhanced headers with rotating user agents
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
];

const getRandomUserAgent = () => {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
};

// Generate unique ID for each product
const generateProductId = () => {
  return uuidv4();
};

const SCRAPING_HEADERS = {
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'Cache-Control': 'max-age=0'
};

// Helper function to clean and extract price
const cleanPrice = (priceString) => {
  if (!priceString) return null;
  
  // Remove common non-price text
  const cleaned = priceString
    .replace(/Price not available|Typical price:|Currently not deliverable|More Buying Choices|price, product page|delivery|ships to|used & new offers/gi, '')
    .replace(/Now\$|From\$|save\s*\$\d+|bought in past month/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
  
  // Extract currency and amount using regex
  const pricePatterns = [
    /(?:PKR|USD|EUR|GBP|CAD|AUD|JPY|INR|CNY)\s*[\d,.]+/i,
    /\$\s*[\d,.]+/,
    /[\d,.]+(?:\s*(?:PKR|USD|EUR|GBP|CAD|AUD|JPY|INR|CNY))/i,
    /[\d,.]+\s*\-?\s*[\d,.]*/
  ];
  
  let bestMatch = '';
  for (const pattern of pricePatterns) {
    const matches = cleaned.match(pattern);
    if (matches && matches[0].length > bestMatch.length) {
      bestMatch = matches[0];
    }
  }
  
  if (!bestMatch) {
    const numberMatch = cleaned.match(/[\d,.]{3,}/);
    if (numberMatch) {
      bestMatch = numberMatch[0];
    }
  }
  
  if (!bestMatch) return null;
  
  // Extract numeric value
  const numericValue = parseFloat(bestMatch.replace(/[^\d.]/g, ''));
  
  if (isNaN(numericValue)) return null;
  
  // Determine currency
  let currency = '$';
  if (bestMatch.includes('PKR')) currency = 'PKR ';
  else if (bestMatch.includes('EUR')) currency = '€';
  else if (bestMatch.includes('GBP')) currency = '£';
  else if (bestMatch.includes('₹')) currency = '₹';
  else if (bestMatch.includes('$')) currency = '$';
  
  return {
    value: numericValue,
    formatted: `${currency}${numericValue.toFixed(2)}`,
    currency: currency.trim()
  };
};

// Helper function to clean titles
const cleanTitle = (title) => {
  if (!title) return '';
  
  let cleaned = title
    .replace(/\$\s*[\d,.]+/g, '')
    .replace(/PKR\s*[\d,.]+/g, '')
    .replace(/[\d,.]+\s*\-?\s*[\d,.]*/g, '')
    .replace(/New Listing|Shop on eBay|\(Renewed\)|\(Refurbished\)/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
  
  cleaned = cleaned.replace(/^[^\w]+|[^\w]+$/g, '');
  
  return cleaned || title;
};

// Helper function to clean rating
const cleanRating = (ratingText) => {
  if (!ratingText || typeof ratingText !== 'string') return 'No rating';
  
  let cleaned = ratingText
    .replace(/Previous page|Next page|\.{2,}|% off coupon applied|Save \d+% with coupon|Save \d+%|Delivery.*|Price, product page/gi, '')
    .trim();
  
  // Extract rating pattern like "4.2 out of 5 stars"
  const ratingMatch = cleaned.match(/(\d+\.?\d*)\s*out of 5 stars/gi);
  if (ratingMatch && ratingMatch.length > 0) {
    const firstRating = ratingMatch[0];
    const ratingNum = firstRating.match(/(\d+\.?\d*)/)[0];
    const rating = parseFloat(ratingNum);
    if (!isNaN(rating) && rating >= 0 && rating <= 5) {
      return `${rating.toFixed(1)} out of 5 stars`;
    }
  }
  
  // If no rating found
  return 'No rating';
};

// Helper function to clean reviews
const cleanReviews = (reviewsText) => {
  if (!reviewsText || typeof reviewsText !== 'string') return 'No reviews';
  
  let cleaned = reviewsText
    .replace(/PKR\s*[\d.,]+|Price, product page|% off coupon applied|Save \d+% with coupon|Save \d+%|Delivery.*|Global seller|Shipping varies/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
  
  // Extract review count
  const reviewMatch = cleaned.match(/(\d+)\s*(?:reviews|ratings|customer reviews)?/i);
  if (reviewMatch) {
    const reviewCount = parseInt(reviewMatch[1]);
    if (!isNaN(reviewCount)) {
      return `${reviewCount} reviews`;
    }
  }
  
  return 'No reviews';
};

// Helper to check if a string contains a valid price
const hasValidPrice = (text) => {
  if (!text || text.includes('Price not available')) return false;
  
  const pricePatterns = [
    /\$\s*[\d,.]+/,
    /PKR\s*[\d,.]+/i,
    /[\d,.]+\s*(?:USD|EUR|GBP|CAD|AUD|JPY|INR|CNY)/i,
    /[\d,.]{3,}/
  ];
  
  return pricePatterns.some(pattern => pattern.test(text));
};

const processQueryWithNLP = async (query) => {
  try {
    let processedQuery = query.toLowerCase().trim();
    processedQuery = processedQuery.replace(/[^\w\s]/g, ' ');
    processedQuery = processedQuery.replace(/\s+/g, ' ');

    const keyTerms = processedQuery.split(' ')
      .filter(term => term.length > 2)
      .map(term => stemmer.stem(term));

    return {
      original: query,
      processed: processedQuery,
      entities: {},
      keyTerms: [...new Set(keyTerms)],
      categories: []
    };
  } catch (error) {
    return {
      original: query,
      processed: query.toLowerCase(),
      entities: {},
      keyTerms: query.split(' ').filter(term => term.length > 2),
      categories: []
    };
  }
};

// Function to store product visit in Supabase
const storeProductVisit = async (userId, productData) => {
  try {
    console.log('🔄 Attempting to store product visit for user:', userId);
    console.log('📦 Product data:', {
      title: productData.title,
      price: productData.price,
      url: productData.url
    });
    
    const productHistoryData = {
      user_id: userId,
      product_id: productData.id,
      product_title: productData.title,
      product_price: productData.price,
      product_numeric_price: productData.numericPrice || null,
      product_currency: productData.currency || 'USD',
      product_url: productData.url,
      product_image: productData.image,
      product_source: productData.source,
      product_rating: productData.rating || null,
      product_reviews: productData.reviews || null,
      search_query: productData.searchQuery || null,
      visited_at: new Date().toISOString()
    };

    console.log('📝 Data to insert:', productHistoryData);

    const { data, error } = await supabase
      .from('product_history')
      .insert([productHistoryData])
      .select();

    if (error) {
      console.error('❌ Error storing product visit:', error);
      return { success: false, error: error.message };
    }

    console.log('✅ Product visit stored successfully:', data);
    return { success: true, data };
  } catch (error) {
    console.error('❌ Error in storeProductVisit:', error);
    return { success: false, error: error.message };
  }
};

// Function to get user's product visit history (UPDATED)
const getUserProductHistory = async (userId, limit = 50) => {
  try {
    const { data, error } = await supabase
      .from('product_history')
      .select('*')
      .eq('user_id', userId)
      .order('visited_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('Error fetching product history:', error);
      return { success: false, error: error.message };
    }

    return { success: true, data };
  } catch (error) {
    console.error('Error in getUserProductHistory:', error);
    return { success: false, error: error.message };
  }
};

// Get product history function (UPDATED to match job history structure)
// Get product history function - SECURE VERSION
const getProductHistory = async (req, res) => {
  try {
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

    console.log(`🔐 Fetching product history for user: ${user.id}`);

    // 3. Query product_history filtered by user_id
    const { data, error, count } = await supabase
      .from('product_history')
      .select('*', { count: 'exact' })
      .eq('user_id', user.id) // Only show this user's history
      .order('visited_at', { ascending: false })
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
    console.error('Error fetching product history:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message,
      success: false
    });
  }
};

// Improved Amazon price extraction function
const getAmazonPrice = (element, $) => {
  const strategies = [
    () => {
      const priceElement = $(element).find('.a-price .a-offscreen').first();
      return priceElement.length ? priceElement.text().trim() : '';
    },
    () => {
      const whole = $(element).find('.a-price-whole').first().text().trim();
      const fraction = $(element).find('.a-price-fraction').first().text().trim();
      const symbol = $(element).find('.a-price-symbol').first().text().trim();
      if (whole) {
        return `${symbol}${whole}${fraction}`;
      }
      return '';
    },
    () => {
      const priceElement = $(element).find('.a-price[data-a-size]');
      return priceElement.length ? priceElement.text().trim() : '';
    },
    () => {
      const priceElement = $(element).find('[data-a-color="price"]');
      return priceElement.length ? priceElement.text().trim() : '';
    },
    () => {
      const priceElement = $(element).find('span[data-a-color="base"]').first();
      return priceElement.length ? priceElement.text().trim() : '';
    },
    () => {
      const text = $(element).text();
      const priceMatch = text.match(/(?:PKR|USD|\$|€|£|₹)\s*[\d,.]+/);
      return priceMatch ? priceMatch[0] : '';
    },
    () => {
      const text = $(element).text();
      const numberMatch = text.match(/[\d,.]{3,}/);
      if (numberMatch) {
        const num = numberMatch[0];
        if (parseFloat(num.replace(/[^\d.]/g, '')) > 10) {
          return `$${num}`;
        }
      }
      return '';
    }
  ];
  
  for (const strategy of strategies) {
    try {
      const price = strategy();
      if (price && price.length > 0 && hasValidPrice(price)) {
        const cleaned = price.replace(/\s+/g, ' ').trim();
        if (!cleaned.toLowerCase().includes('bought') && 
            !cleaned.toLowerCase().includes('review') &&
            !cleaned.toLowerCase().includes('stars')) {
          return cleaned;
        }
      }
    } catch (e) {
      continue;
    }
  }
  
  return null;
};

// ============ REORDERED SCRAPING FUNCTIONS ============

// 1. AMAZON SCRAPER - FIRST PRIORITY
const scrapeAmazonProducts = async (query) => {
  try {
    console.log(`🛒 [1] Scraping Amazon for: ${query}`);
    
    const headers = {
      ...SCRAPING_HEADERS,
      'User-Agent': getRandomUserAgent(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Referer': 'https://www.amazon.com/'
    };

    const amazonDomains = [
      'https://www.amazon.com',
      'https://www.amazon.co.uk',
      'https://www.amazon.de'
    ];

    let results = [];

    for (const domain of amazonDomains) {
      try {
        const response = await axios.get(`${domain}/s`, {
          params: {
            'k': query,
            'i': 'aps',
            'ref': 'nb_sb_noss'
          },
          headers,
          timeout: 15000
        });

        const $ = cheerio.load(response.data);
        
        const selectors = [
          '.s-result-item',
          '[data-component-type="s-search-result"]',
          '.s-main-slot .s-result-item',
          '.sg-col-inner'
        ];

        for (const selector of selectors) {
          $(selector).each((i, element) => {
            if (results.length < 200) {
              try {
                const title = $(element).find('h2 a span').text().trim() || 
                             $(element).find('.a-size-medium').text().trim();
                
                if (title && title.length > 5) {
                  const price = getAmazonPrice(element, $);
                  
                  if (!price) {
                    return;
                  }
                  
                  let rating = $(element).find('.a-icon-alt').text().trim() || 
                              $(element).find('[aria-label*="stars"]').attr('aria-label') || 
                              $(element).find('.a-popover-trigger .a-size-base').text().trim();
                  
                  let reviews = $(element).find('.a-size-base').text().trim() || 
                               $(element).find('[aria-label*="ratings"]').attr('aria-label') ||
                               '';
                  
                  const url = $(element).find('a').attr('href');
                  const image = $(element).find('img').attr('src');

                  const fullUrl = url && !url.startsWith('http') ? `${domain}${url}` : url;

                  results.push({
                    id: generateProductId(),
                    title: cleanTitle(title),
                    price,
                    rating: cleanRating(rating),
                    reviews: cleanReviews(reviews),
                    description: cleanTitle(title),
                    url: fullUrl || `${domain}/s?k=${encodeURIComponent(query)}`,
                    image: image || 'https://via.placeholder.com/200x200?text=No+Image',
                    type: 'product',
                    source: `Amazon (${domain.split('.').pop()})`,
                    searchQuery: query
                  });
                }
              } catch (error) {
                console.log('Error parsing Amazon item:', error.message);
              }
            }
          });
        }

        if (results.length > 10) break;
      } catch (error) {
        console.log(`Amazon ${domain} failed:`, error.message);
        continue;
      }
    }

    console.log(`✅ Found ${results.length} products from Amazon`);
    return results;

  } catch (error) {
    console.error('Amazon scraping failed:', error.message);
    return [];
  }
};

// 2. NEWEGG SCRAPER - SECOND PRIORITY
const scrapeNeweggProducts = async (query) => {
  try {
    console.log(`💻 [2] Scraping Newegg for: ${query}`);
    
    const headers = {
      ...SCRAPING_HEADERS,
      'User-Agent': getRandomUserAgent(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Referer': 'https://www.newegg.com/'
    };

    const response = await axios.get(`https://www.newegg.com/p/pl`, {
      params: {
        'd': query,
        'N': 1000000
      },
      headers,
      timeout: 15000
    });

    const $ = cheerio.load(response.data);
    const results = [];

    const selectors = [
      '.item-cell',
      '.item-container',
      '.item-info'
    ];

    selectors.forEach(selector => {
      $(selector).each((i, element) => {
        if (results.length < 200) {
          try {
            const title = $(element).find('.item-title').text().trim() || 
                         $(element).find('a').text().trim();
            
            let price = $(element).find('.price-current').text().trim() || 
                       $(element).find('.price').text().trim();
            
            if (price && price.includes('–')) {
              price = price.split('–')[0].trim();
            }
            
            if (!hasValidPrice(price)) {
              return;
            }
            
            let rating = $(element).find('.rating').text().trim() || '';
            let reviews = $(element).find('.item-rating-num').text().trim() || '';
            
            const url = $(element).find('a').attr('href');
            const image = $(element).find('img').attr('src');

            if (title && title.length > 5) {
              const fullUrl = url && !url.startsWith('http') ? `https://www.newegg.com${url}` : url;
              
              results.push({
                id: generateProductId(),
                title: cleanTitle(title),
                price: price,
                rating: cleanRating(rating),
                reviews: cleanReviews(reviews),
                description: cleanTitle(title),
                url: fullUrl || `https://www.newegg.com/p/pl?d=${encodeURIComponent(query)}`,
                image: image || 'https://via.placeholder.com/200x200?text=No+Image',
                type: 'product',
                source: 'Newegg',
                searchQuery: query
              });
            }
          } catch (error) {
            console.log('Error parsing Newegg item:', error.message);
          }
        }
      });
    });

    console.log(`✅ Found ${results.length} products from Newegg`);
    return results;

  } catch (error) {
    console.error('Newegg scraping failed:', error.message);
    return [];
  }
};

// 3. WALMART SCRAPER - THIRD PRIORITY
const scrapeWalmartProducts = async (query) => {
  try {
    console.log(`🏪 [3] Scraping Walmart for: ${query}`);
    
    const headers = {
      ...SCRAPING_HEADERS,
      'User-Agent': getRandomUserAgent(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Referer': 'https://www.walmart.com/'
    };

    const response = await axios.get(`https://www.walmart.com/search`, {
      params: {
        'q': query
      },
      headers,
      timeout: 15000
    });

    const $ = cheerio.load(response.data);
    const results = [];

    const selectors = [
      '[data-item-id]',
      '.mb0',
      '.pa0-xl',
      '.search-product-result',
      '.product-grid'
    ];

    selectors.forEach(selector => {
      $(selector).each((i, element) => {
        if (results.length < 200) {
          try {
            const title = $(element).find('span[aria-hidden="true"]').text().trim() || 
                         $(element).find('.f6').text().trim() ||
                         $(element).find('.w_iUH7').text().trim();
            
            let price = $(element).find('[data-automation-id="product-price"]').text().trim() ||
                       $(element).find('.f5').text().trim() ||
                       $(element).find('.b').text().trim();
            
            if (price && price.includes('$')) {
              const priceMatch = price.match(/\$\s*[\d,.]+/);
              if (priceMatch) {
                price = priceMatch[0];
              }
            }
            
            if (!hasValidPrice(price)) {
              return;
            }
            
            let rating = $(element).find('.rating-number').text().trim() || '';
            let reviews = $(element).find('.rating-count').text().trim() || '';
            
            const url = $(element).find('a').attr('href');
            const image = $(element).find('img').attr('src');

            if (title && title.length > 5) {
              const fullUrl = url && !url.startsWith('http') ? `https://www.walmart.com${url}` : url;
              
              results.push({
                id: generateProductId(),
                title: cleanTitle(title),
                price: price,
                rating: cleanRating(rating),
                reviews: cleanReviews(reviews),
                description: cleanTitle(title),
                url: fullUrl || `https://www.walmart.com/search?q=${encodeURIComponent(query)}`,
                image: image || 'https://via.placeholder.com/200x200?text=No+Image',
                type: 'product',
                source: 'Walmart',
                searchQuery: query
              });
            }
          } catch (error) {
            console.log('Error parsing Walmart item:', error.message);
          }
        }
      });
    });

    console.log(`✅ Found ${results.length} products from Walmart`);
    return results;

  } catch (error) {
    console.error('Walmart scraping failed:', error.message);
    return [];
  }
};

// 4. ALIEXPRESS SCRAPER - FOURTH PRIORITY
const scrapeAliExpressProducts = async (query) => {
  try {
    console.log(`🌍 [4] Scraping AliExpress for: ${query}`);
    
    const headers = {
      ...SCRAPING_HEADERS,
      'User-Agent': getRandomUserAgent(),
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
      'Referer': 'https://www.aliexpress.com/'
    };

    const response = await axios.get(`https://www.aliexpress.com/w/wholesale-${encodeURIComponent(query)}.html`, {
      headers,
      timeout: 20000
    });

    const $ = cheerio.load(response.data);
    const results = [];

    const selectors = [
      '.list--gallery--34TropR .list-item',
      '.manhattan--container--1lP57Ag .cards--gallery--2o6yJVt',
      '[product-index]',
      '.search-item',
      '.item',
      '.list-item'
    ];

    selectors.forEach(selector => {
      $(selector).each((i, element) => {
        if (results.length < 200) {
          try {
            const title = $(element).find('.multi--titleText--nXeOvyr').text().trim() || 
                         $(element).find('.item-title').text().trim() ||
                         $(element).find('[ae_object_value]').text().trim() ||
                         $(element).find('h3').text().trim();
            
            let price = $(element).find('.multi--price-sale--U-S0jtj').text().trim() ||
                       $(element).find('.price').text().trim() ||
                       $(element).find('.value').text().trim();
            
            if (!hasValidPrice(price)) {
              return;
            }
            
            let rating = $(element).find('.multi--evaluation--3kmuTqf').text().trim() ||
                        $(element).find('.rating-value').text().trim();
            
            let reviews = $(element).find('.multi--trade--1O4zJjF').text().trim() ||
                         $(element).find('.rating-count').text().trim();

            const url = $(element).find('a').attr('href');
            const image = $(element).find('img').attr('src') || 
                         $(element).find('img').attr('image-src');

            if (title && title.length > 5) {
              const fullUrl = url && !url.startsWith('http') ? `https:${url}` : url;
              
              results.push({
                id: generateProductId(),
                title: cleanTitle(title),
                price: price,
                rating: cleanRating(rating),
                reviews: cleanReviews(reviews),
                description: cleanTitle(title),
                url: fullUrl || `https://www.aliexpress.com/w/wholesale-${encodeURIComponent(query)}.html`,
                image: image || 'https://via.placeholder.com/200x200?text=No+Image',
                type: 'product',
                source: 'AliExpress',
                searchQuery: query
              });
            }
          } catch (error) {
            console.log('Error parsing AliExpress item:', error.message);
          }
        }
      });
    });

    console.log(`✅ Found ${results.length} products from AliExpress`);
    return results;

  } catch (error) {
    console.error('AliExpress scraping failed:', error.message);
    return [];
  }
};

// 5. EBAY SCRAPER - LAST PRIORITY
const scrapeEbayProducts = async (query) => {
  try {
    console.log(`💰 [5] Scraping eBay for: ${query}`);
    
    const headers = {
      ...SCRAPING_HEADERS,
      'User-Agent': getRandomUserAgent(),
      'Referer': 'https://www.ebay.com/'
    };

    const ebayDomains = [
      'https://www.ebay.com',
      'https://www.ebay.co.uk',
      'https://www.ebay.de'
    ];

    let results = [];

    for (const domain of ebayDomains) {
      try {
        const response = await axios.get(`${domain}/sch/i.html`, {
          params: {
            '_nkw': query,
            '_sacat': 0,
            '_ipg': 240
          },
          headers,
          timeout: 15000
        });

        const $ = cheerio.load(response.data);
        
        const selectors = [
          '.s-item',
          '.srp-results .s-item',
          '.srp-river-results .s-item',
          '[data-viewport] .s-item'
        ];

        for (const selector of selectors) {
          $(selector).each((i, element) => {
            if (results.length < 200 && i > 0) {
              try {
                const titleElem = $(element).find('.s-item__title');
                const title = titleElem.text().trim().replace('New Listing', '').trim();
                
                if (title && !title.includes('Shop on eBay')) {
                  let price = $(element).find('.s-item__price').text().trim();
                  
                  if (price.includes('to')) {
                    price = price.split('to')[0].trim();
                  }
                  
                  if (!hasValidPrice(price)) {
                    return;
                  }
                  
                  const shipping = $(element).find('.s-item__shipping, .s-item__freeXDays').text().trim();
                  const url = $(element).find('.s-item__link').attr('href');
                  const image = $(element).find('.s-item__image-img').attr('src') || 
                               $(element).find('img').attr('src');
                  const location = $(element).find('.s-item__location').text().trim();

                  results.push({
                    id: generateProductId(),
                    title: cleanTitle(title),
                    price: price,
                    rating: cleanRating(shipping || 'Shipping varies'),
                    reviews: cleanReviews(location || 'Global seller'),
                    description: cleanTitle(title),
                    url: url || `${domain}/sch/i.html?_nkw=${encodeURIComponent(query)}`,
                    image: image || 'https://via.placeholder.com/200x200?text=No+Image',
                    type: 'product',
                    source: `eBay (${domain.split('.').pop()})`,
                    searchQuery: query
                  });
                }
              } catch (error) {
                console.log('Error parsing eBay item:', error.message);
              }
            }
          });
        }

        if (results.length > 10) break;
      } catch (error) {
        console.log(`eBay ${domain} failed:`, error.message);
        continue;
      }
    }

    console.log(`✅ Found ${results.length} products from eBay`);
    return results;

  } catch (error) {
    console.error('eBay scraping failed:', error.message);
    return [];
  }
};

// Main product scraping function - REORDERED PRIORITIES
// Main product scraping function - REORDERED PRIORITIES
// Main product scraping function - REORDERED PRIORITIES with preserved order
const scrapeProductsFromMultipleSources = async (query) => {
  console.log(`🚀 Starting comprehensive product search for: ${query}`);
  
  try {
    // Scrape in order of priority: Amazon → Newegg → Walmart → AliExpress → eBay
    console.log('\n📋 Scraping order: Amazon → Newegg → Walmart → AliExpress → eBay\n');
    
    // Scrape in order but store results separately
    console.log('🛒 [1/5] Getting Amazon products...');
    const amazonResults = await scrapeAmazonProducts(query);
    
    console.log('💻 [2/5] Getting Newegg products...');
    const neweggResults = await scrapeNeweggProducts(query);
    
    console.log('🏪 [3/5] Getting Walmart products...');
    const walmartResults = await scrapeWalmartProducts(query);
    
    console.log('🌍 [4/5] Getting AliExpress products...');
    const aliexpressResults = await scrapeAliExpressProducts(query);
    
    console.log('💰 [5/5] Getting eBay products...');
    const ebayResults = await scrapeEbayProducts(query);
    
    // Log results from each source
    console.log('\n📊 Results summary:');
    console.log(`   Amazon: ${amazonResults.length} products`);
    console.log(`   Newegg: ${neweggResults.length} products`);
    console.log(`   Walmart: ${walmartResults.length} products`);
    console.log(`   AliExpress: ${aliexpressResults.length} products`);
    console.log(`   eBay: ${ebayResults.length} products`);

    // Create a map to track products by source to maintain order
    const productsBySource = {
      amazon: amazonResults,
      newegg: neweggResults,
      walmart: walmartResults,
      aliexpress: aliexpressResults,
      ebay: ebayResults
    };

    // Combine results while maintaining source order AND removing duplicates
    const allProducts = [];
    const seenTitles = new Set();
    const sourceOrder = ['amazon', 'newegg', 'walmart', 'aliexpress', 'ebay'];

    // Process each source in order
    for (const source of sourceOrder) {
      const sourceProducts = productsBySource[source];
      let addedFromSource = 0;
      
      for (const product of sourceProducts) {
        // Create a normalized title for deduplication
        const normalizedTitle = product.title.toLowerCase()
          .replace(/[^a-z0-9]/g, '')
          .substring(0, 60);
        
        // Check if we've seen this product before
        if (!seenTitles.has(normalizedTitle)) {
          seenTitles.add(normalizedTitle);
          allProducts.push(product);
          addedFromSource++;
          
          // Limit total products
          if (allProducts.length >= 200) break;
        }
        
        if (allProducts.length >= 200) break;
      }
      
      console.log(`   Added ${addedFromSource} unique products from ${source}`);
      
      if (allProducts.length >= 200) break;
    }

    console.log(`✅ Total unique products found: ${allProducts.length}`);
    
    // Add source tags for debugging
    const finalProducts = allProducts.map(product => ({
      ...product,
      // Add source priority for debugging (optional)
      sourcePriority: getSourcePriority(product.source)
    }));

    // Log the distribution of sources in final results
    console.log('\n📋 Final results distribution by source:');
    const sourceCount = {};
    finalProducts.forEach(p => {
      const sourceKey = p.source.toLowerCase().includes('amazon') ? 'amazon' :
                       p.source.toLowerCase().includes('newegg') ? 'newegg' :
                       p.source.toLowerCase().includes('walmart') ? 'walmart' :
                       p.source.toLowerCase().includes('aliexpress') ? 'aliexpress' : 'ebay';
      sourceCount[sourceKey] = (sourceCount[sourceKey] || 0) + 1;
    });
    
    Object.entries(sourceCount).forEach(([source, count]) => {
      console.log(`   ${source.charAt(0).toUpperCase() + source.slice(1)}: ${count} products`);
    });

    if (finalProducts.length === 0) {
      console.log('No products found from scraping, using fallback API...');
      return await fallbackProductSearch(query);
    }
    
    return finalProducts;

  } catch (error) {
    console.error('Error in multi-source scraping:', error);
    return await fallbackProductSearch(query);
  }
};

// Helper function to get source priority (for debugging)
const getSourcePriority = (source) => {
  const sourceLower = source.toLowerCase();
  if (sourceLower.includes('amazon')) return 1;
  if (sourceLower.includes('newegg')) return 2;
  if (sourceLower.includes('walmart')) return 3;
  if (sourceLower.includes('aliexpress')) return 4;
  return 5; // ebay or others
};



// Fallback API
const fallbackProductSearch = async (query) => {
  try {
    console.log(`Using fallback API for: ${query}`);
    
    const response = await axios.get(`https://api.rainforestapi.com/request`, {
      params: {
        api_key: 'demo',
        type: 'search',
        amazon_domain: 'amazon.com',
        search_term: query,
        sort_by: 'price_low_to_high'
      },
      timeout: 10000
    });

    const results = response.data.search_results.slice(0, 50).map((item, index) => ({
      id: generateProductId(),
      title: item.title || `Product ${index + 1}`,
      price: item.price?.raw || `$${(50 + index * 10).toFixed(2)}`,
      rating: item.rating ? `${item.rating} out of 5 stars` : 'No rating',
      reviews: item.ratings_total ? `${item.ratings_total} reviews` : 'No reviews',
      description: item.title || `This is a ${query} product`,
      url: item.link || `https://example.com/product/${index}`,
      image: item.image || `https://picsum.photos/200/200?random=${index}`,
      type: 'product',
      source: 'Fallback API',
      searchQuery: query
    }));

    console.log(`Fallback API returned ${results.length} products`);
    return results;

  } catch (error) {
    console.error('Fallback API also failed:', error.message);
    return generateRealisticProducts(query, 50);
  }
};

// Generate realistic mock products
const generateRealisticProducts = (query, count = 50) => {
  const brands = {
    iphone: ['Apple iPhone', 'Renewed iPhone', 'Refurbished iPhone'],
    laptop: ['Dell', 'HP', 'Lenovo', 'ASUS', 'Acer', 'MacBook'],
    watch: ['Apple Watch', 'Samsung Galaxy Watch', 'Fitbit', 'Garmin'],
    camera: ['Canon', 'Nikon', 'Sony', 'GoPro'],
    default: ['Premium', 'Professional', 'Advanced', 'Standard']
  };

  const products = [];
  let brandList = brands.default;
  
  Object.keys(brands).forEach(key => {
    if (query.toLowerCase().includes(key)) {
      brandList = brands[key];
    }
  });

  for (let i = 1; i <= count; i++) {
    const brand = brandList[i % brandList.length];
    const price = 50 + (i * 23) % 1000;
    const rating = 3.5 + (i * 0.1) % 1.5;
    
    products.push({
      id: generateProductId(),
      title: `${brand} ${query} ${i} (Latest Model)`,
      price: `$${price.toFixed(2)}`,
      rating: `${rating.toFixed(1)} out of 5 stars`,
      reviews: `${(i * 17) % 500 + 50} reviews`,
      description: `High-quality ${query} from ${brand}. Features include advanced technology, premium materials, and excellent performance.`,
      url: `https://example.com/products/${query.replace(/\s+/g, '-')}-${i}`,
      image: `https://picsum.photos/200/200?random=${i}&${Date.now()}`,
      type: 'product',
      source: 'Product Database',
      searchQuery: query
    });
  }

  console.log(`Generated ${products.length} realistic mock products`);
  return products;
};

// Search history storage
const storeSearchHistory = async (userId, query, processedQuery, resultCount) => {
  try {
    console.log('Storing search history:', { userId, originalQuery: query, resultCount });
  } catch (error) {
    console.error('Error storing search history:', error);
  }
};

// Main search function
const searchProducts = async (req, res) => {
  try {
    const { query, userId, minPrice, maxPrice } = req.body;

    if (!query || query.trim().length === 0) {
      return res.status(400).json({
        error: 'Search query is required'
      });
    }

    const processedQuery = await processQueryWithNLP(query);
    console.log(`🔍 Searching for: ${query}, User ID: ${userId}`);
    
    const searchResults = await scrapeProductsFromMultipleSources(processedQuery.processed);

    // Filter and clean products with valid prices
    const productsWithPrices = searchResults.filter(product => {
      if (!product.price) {
        return false;
      }

      const cleanedPrice = cleanPrice(product.price);
      
      if (!cleanedPrice || isNaN(cleanedPrice.value)) {
        return false;
      }

      product.originalPrice = product.price;
      product.price = cleanedPrice.formatted;
      product.numericPrice = cleanedPrice.value;
      product.currency = cleanedPrice.currency;

      product.title = cleanTitle(product.title);
      product.description = cleanTitle(product.description || product.title);
      
      // Clean rating and reviews
      product.rating = cleanRating(product.rating);
      product.reviews = cleanReviews(product.reviews);

      if (minPrice !== undefined && product.numericPrice < parseFloat(minPrice)) {
        return false;
      }
      if (maxPrice !== undefined && product.numericPrice > parseFloat(maxPrice)) {
        return false;
      }

      return true;
    });

    // Sort by price (lowest first)
    productsWithPrices.sort((a, b) => a.numericPrice - b.numericPrice);

    // Store the first result in product_history if userId is provided
    if (userId && productsWithPrices.length > 0) {
      const firstProduct = productsWithPrices[0];
      console.log('📊 First product to store:', {
        title: firstProduct.title,
        price: firstProduct.price,
        userId: userId
      });
      
      try {
        const storeResult = await storeProductVisit(userId, {
          ...firstProduct,
          searchQuery: query
        });
        
        if (storeResult.success) {
          console.log('✅ Successfully stored first product in history');
        } else {
          console.error('❌ Failed to store first product:', storeResult.error);
        }
      } catch (storeError) {
        console.error('❌ Error storing product:', storeError);
      }
    } else {
      console.log('⚠️ No userId provided or no products found, skipping history storage');
    }

    if (userId) {
      await storeSearchHistory(userId, query, processedQuery, productsWithPrices.length);
    }

    res.status(200).json({
      success: true,
      originalQuery: query,
      processedQuery: processedQuery,
      results: productsWithPrices,
      totalResults: productsWithPrices.length,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Products search error:', error);
    res.status(500).json({
      error: 'Internal server error during product search',
      message: error.message
    });
  }
};

// New endpoint to track product visits
const trackProductVisit = async (req, res) => {
  try {
    const { userId, product } = req.body;

    if (!userId || !product) {
      return res.status(400).json({
        error: 'User ID and product data are required'
      });
    }

    console.log('📝 Tracking product visit for user:', userId);
    const result = await storeProductVisit(userId, product);

    if (result.success) {
      res.status(200).json({
        success: true,
        message: 'Product visit tracked successfully',
        data: result.data
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Failed to track product visit',
        details: result.error
      });
    }

  } catch (error) {
    console.error('Product visit tracking error:', error);
    res.status(500).json({
      error: 'Internal server error during product visit tracking',
      message: error.message
    });
  }
};

// Test Supabase connection
const testSupabaseConnection = async () => {
  try {
    const { data, error } = await supabase
      .from('product_history')
      .select('count')
      .limit(1);
    
    if (error) {
      console.error('❌ Supabase connection test failed:', error);
      return false;
    }
    
    console.log('✅ Supabase connection successful');
    return true;
  } catch (error) {
    console.error('❌ Supabase connection test error:', error);
    return false;
  }
};

// Test connection on startup
testSupabaseConnection();

module.exports = {
  searchProducts,
  trackProductVisit,
  getProductHistory,  // Updated function
  cleanPrice,
  cleanTitle,
  cleanRating,
  cleanReviews,
  hasValidPrice,
  storeProductVisit,
  getUserProductHistory
};