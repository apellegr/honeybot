/**
 * Fetch and unify adversarial prompt datasets from research sources
 *
 * Sources:
 * - jailbreak_llms (TrustAIRLab) - 1,405 jailbreak prompts
 * - WildGuardMix (AllenAI) - 92K safety examples
 * - ToxicChat (LMSYS) - 10K real user prompts
 * - AdvBench - 520 harmful behaviors
 * - JailbreakBench - 200 behaviors
 */

const fs = require('fs');
const path = require('path');

const OUTPUT_DIR = path.join(__dirname, '../tests/redteam/research');

// Ensure output directory exists
if (!fs.existsSync(OUTPUT_DIR)) {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

// Hugging Face API base
const HF_API = 'https://datasets-server.huggingface.co';

/**
 * Fetch dataset from Hugging Face
 */
async function fetchHFDataset(dataset, config = 'default', split = 'train', offset = 0, length = 100) {
  const url = `${HF_API}/rows?dataset=${encodeURIComponent(dataset)}&config=${config}&split=${split}&offset=${offset}&length=${length}`;

  console.log(`  Fetching ${dataset} (offset ${offset}, limit ${length})...`);

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${dataset}: ${response.status}`);
  }

  const data = await response.json();
  return data.rows || [];
}

/**
 * Fetch all rows from a dataset (paginated)
 */
async function fetchAllRows(dataset, config = 'default', split = 'train', maxRows = 5000) {
  const allRows = [];
  const pageSize = 100;
  let offset = 0;

  while (offset < maxRows) {
    try {
      const rows = await fetchHFDataset(dataset, config, split, offset, pageSize);
      if (rows.length === 0) break;

      allRows.push(...rows);
      offset += rows.length;

      // Rate limiting
      await new Promise(r => setTimeout(r, 200));

      if (rows.length < pageSize) break;
    } catch (error) {
      console.error(`  Error at offset ${offset}: ${error.message}`);
      break;
    }
  }

  return allRows;
}

/**
 * Fetch jailbreak_llms dataset
 */
async function fetchJailbreakLLMs() {
  console.log('\n📥 Fetching jailbreak_llms (TrustAIRLab)...');

  const prompts = [];

  // Try different configs
  const configs = [
    'jailbreak_2023_05_07',
    'jailbreak_2023_12_25',
    'prompts_2023_12_25'
  ];

  for (const config of configs) {
    try {
      const rows = await fetchAllRows('TrustAIRLab/in-the-wild-jailbreak-prompts', config, 'train', 2000);

      for (const row of rows) {
        const data = row.row;
        if (data.prompt || data.jailbreak) {
          prompts.push({
            source: 'jailbreak_llms',
            category: data.community || config,
            prompt: data.prompt || data.jailbreak,
            label: 'malicious',
            metadata: {
              platform: data.platform,
              date: data.date
            }
          });
        }
      }
      console.log(`  Got ${rows.length} rows from ${config}`);
    } catch (error) {
      console.log(`  Skipping ${config}: ${error.message}`);
    }
  }

  console.log(`  Total jailbreak_llms prompts: ${prompts.length}`);
  return prompts;
}

/**
 * Fetch WildGuardMix dataset
 */
async function fetchWildGuardMix() {
  console.log('\n📥 Fetching WildGuardMix (AllenAI)...');

  const prompts = [];

  // Fetch training data
  try {
    const rows = await fetchAllRows('allenai/wildguardmix', 'wildguardtrain', 'train', 5000);

    for (const row of rows) {
      const data = row.row;
      if (data.prompt) {
        prompts.push({
          source: 'wildguardmix',
          category: data.subcategory || 'unknown',
          prompt: data.prompt,
          response: data.response,
          label: data.prompt_harm_label === 'harmful' ? 'malicious' : 'benign',
          adversarial: data.adversarial,
          metadata: {
            response_harm: data.response_harm_label,
            response_refusal: data.response_refusal_label
          }
        });
      }
    }
    console.log(`  Got ${rows.length} rows from wildguardtrain`);
  } catch (error) {
    console.log(`  Error fetching wildguardtrain: ${error.message}`);
  }

  // Fetch test data
  try {
    const rows = await fetchAllRows('allenai/wildguardmix', 'wildguardtest', 'test', 2000);

    for (const row of rows) {
      const data = row.row;
      if (data.prompt) {
        prompts.push({
          source: 'wildguardmix_test',
          category: data.subcategory || 'unknown',
          prompt: data.prompt,
          response: data.response,
          label: data.prompt_harm_label === 'harmful' ? 'malicious' : 'benign',
          adversarial: data.adversarial,
          metadata: {
            response_harm: data.response_harm_label,
            response_refusal: data.response_refusal_label
          }
        });
      }
    }
    console.log(`  Got ${rows.length} rows from wildguardtest`);
  } catch (error) {
    console.log(`  Error fetching wildguardtest: ${error.message}`);
  }

  console.log(`  Total WildGuardMix prompts: ${prompts.length}`);
  return prompts;
}

/**
 * Fetch ToxicChat dataset
 */
async function fetchToxicChat() {
  console.log('\n📥 Fetching ToxicChat (LMSYS)...');

  const prompts = [];

  try {
    const rows = await fetchAllRows('lmsys/toxic-chat', 'toxicchat0124', 'train', 5000);

    for (const row of rows) {
      const data = row.row;
      if (data.user_input) {
        prompts.push({
          source: 'toxicchat',
          category: data.jailbreaking ? 'jailbreak' : (data.toxicity ? 'toxic' : 'benign'),
          prompt: data.user_input,
          label: (data.toxicity === 1 || data.jailbreaking === 1) ? 'malicious' : 'benign',
          metadata: {
            toxicity: data.toxicity,
            jailbreaking: data.jailbreaking,
            model_output: data.model_output
          }
        });
      }
    }
    console.log(`  Got ${rows.length} rows`);
  } catch (error) {
    console.log(`  Error: ${error.message}`);
  }

  console.log(`  Total ToxicChat prompts: ${prompts.length}`);
  return prompts;
}

/**
 * Fetch AdvBench dataset
 */
async function fetchAdvBench() {
  console.log('\n📥 Fetching AdvBench...');

  const prompts = [];

  try {
    const rows = await fetchAllRows('walledai/AdvBench', 'default', 'train', 1000);

    for (const row of rows) {
      const data = row.row;
      if (data.prompt || data.goal) {
        prompts.push({
          source: 'advbench',
          category: 'harmful_instruction',
          prompt: data.prompt || data.goal,
          label: 'malicious',
          metadata: {
            target: data.target
          }
        });
      }
    }
    console.log(`  Got ${rows.length} rows`);
  } catch (error) {
    console.log(`  Error: ${error.message}`);
  }

  console.log(`  Total AdvBench prompts: ${prompts.length}`);
  return prompts;
}

/**
 * Fetch additional datasets
 */
async function fetchAdditionalDatasets() {
  console.log('\n📥 Fetching additional datasets...');

  const prompts = [];

  // SPML Chatbot Prompt Injection
  try {
    const rows = await fetchAllRows('reshabhs/SPML_Chatbot_Prompt_Injection', 'default', 'train', 1000);

    for (const row of rows) {
      const data = row.row;
      if (data.text || data.prompt) {
        prompts.push({
          source: 'spml_prompt_injection',
          category: 'prompt_injection',
          prompt: data.text || data.prompt,
          label: data.label === 1 ? 'malicious' : 'benign',
          metadata: {}
        });
      }
    }
    console.log(`  SPML Prompt Injection: ${rows.length} rows`);
  } catch (error) {
    console.log(`  SPML error: ${error.message}`);
  }

  // Try JailbreakBench behaviors
  try {
    const rows = await fetchAllRows('JailbreakBench/JBB-Behaviors', 'behaviors', 'harmful', 500);

    for (const row of rows) {
      const data = row.row;
      if (data.Behavior || data.behavior) {
        prompts.push({
          source: 'jailbreakbench',
          category: data.SemanticCategory || data.Category || 'harmful',
          prompt: data.Behavior || data.behavior,
          label: 'malicious',
          metadata: {
            functionalCategory: data.FunctionalCategory
          }
        });
      }
    }
    console.log(`  JailbreakBench: ${rows.length} rows`);
  } catch (error) {
    console.log(`  JailbreakBench error: ${error.message}`);
  }

  return prompts;
}

/**
 * Create unified dataset
 */
async function createUnifiedDataset() {
  console.log('='.repeat(60));
  console.log('FETCHING RESEARCH DATASETS');
  console.log('='.repeat(60));

  const allPrompts = [];

  // Fetch all datasets
  const jailbreakLLMs = await fetchJailbreakLLMs();
  allPrompts.push(...jailbreakLLMs);

  const wildguard = await fetchWildGuardMix();
  allPrompts.push(...wildguard);

  const toxicchat = await fetchToxicChat();
  allPrompts.push(...toxicchat);

  const advbench = await fetchAdvBench();
  allPrompts.push(...advbench);

  const additional = await fetchAdditionalDatasets();
  allPrompts.push(...additional);

  // Deduplicate by prompt text
  console.log('\n🔄 Deduplicating...');
  const seen = new Set();
  const unique = [];

  for (const item of allPrompts) {
    const key = item.prompt.toLowerCase().trim().substring(0, 200);
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
  }

  console.log(`  Removed ${allPrompts.length - unique.length} duplicates`);

  // Split into malicious and benign
  const malicious = unique.filter(p => p.label === 'malicious');
  const benign = unique.filter(p => p.label === 'benign');

  // Get category breakdown
  const categoryBreakdown = {};
  for (const item of unique) {
    const cat = item.category || 'unknown';
    categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1;
  }

  // Get source breakdown
  const sourceBreakdown = {};
  for (const item of unique) {
    sourceBreakdown[item.source] = (sourceBreakdown[item.source] || 0) + 1;
  }

  // Save datasets
  console.log('\n💾 Saving datasets...');

  // Save full unified dataset
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'unified_dataset.json'),
    JSON.stringify(unique, null, 2)
  );

  // Save malicious only
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'malicious_research.json'),
    JSON.stringify(malicious, null, 2)
  );

  // Save benign only
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'benign_research.json'),
    JSON.stringify(benign, null, 2)
  );

  // Save text files for easy review
  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'malicious_research.txt'),
    malicious.map(p => p.prompt).join('\n\n---\n\n')
  );

  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'benign_research.txt'),
    benign.map(p => p.prompt).join('\n\n---\n\n')
  );

  // Save metadata
  const metadata = {
    timestamp: new Date().toISOString(),
    totalPrompts: unique.length,
    maliciousCount: malicious.length,
    benignCount: benign.length,
    sourceBreakdown,
    categoryBreakdown: Object.entries(categoryBreakdown)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 30)
      .reduce((obj, [k, v]) => ({ ...obj, [k]: v }), {})
  };

  fs.writeFileSync(
    path.join(OUTPUT_DIR, 'metadata.json'),
    JSON.stringify(metadata, null, 2)
  );

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('SUMMARY');
  console.log('='.repeat(60));
  console.log(`
Total unique prompts: ${unique.length}
  - Malicious: ${malicious.length}
  - Benign: ${benign.length}

By Source:`);

  for (const [source, count] of Object.entries(sourceBreakdown).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${source}: ${count}`);
  }

  console.log(`\nTop Categories:`);
  const sortedCats = Object.entries(categoryBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 15);
  for (const [cat, count] of sortedCats) {
    console.log(`  ${cat}: ${count}`);
  }

  console.log(`\nFiles saved to: ${OUTPUT_DIR}`);
  console.log('  - unified_dataset.json');
  console.log('  - malicious_research.json');
  console.log('  - benign_research.json');
  console.log('  - malicious_research.txt');
  console.log('  - benign_research.txt');
  console.log('  - metadata.json');
}

createUnifiedDataset().catch(console.error);
