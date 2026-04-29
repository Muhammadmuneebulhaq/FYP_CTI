# Complete Workflow - Entity & Relationship Extraction + Merging

This directory contains a complete pipeline for extracting and merging cyber threat intelligence (CTI) data.

## 📁 Directory Structure

```
new_version/
├── Data/                              # Input CTI documents (.txt files)
├── results/                           # Entity extraction outputs
│   ├── merged/                        # Main entity extraction results
│   ├── ioc/                          # IOC indicators
│   ├── kb/                           # Knowledge base matches
│   ├── novel/                        # Novel entities
│   └── attack_ttp/                   # MITRE ATT&CK mappings
├── relationship/                      # Relationship extraction outputs
├── merged_final/                      # Final merged results (output)
├── config.json                        # TIRE model configuration
├── model_weights.pth                  # TIRE model weights
└── Scripts:
    ├── run_tire.py                    # Core TIRE model
    ├── process_documents.py           # Extract relationships
    ├── merge_entity_relationship_data.py  # Merge entities + relations
    ├── analyze_results.py             # Analysis utilities
    └── visualize_results.py           # Create visualizations
```

## 🚀 Complete Workflow

### Step 1: Relationship Extraction (Already Done)

The `relationship/` folder already contains relationship extraction results from the TIRE model.

If you need to re-run:

```bash
python process_documents.py
```

### Step 2: Merge Entity and Relationship Data ⭐

**This is the main step you need to run:**

```bash
python merge_entity_relationship_data.py
```

This script:

- ✅ Loads entity data from `results/merged/` and related folders
- ✅ Loads relationship data from `relationship/`
- ✅ Validates entities across both models
- ✅ Filters relationships to keep only validated entities
- ✅ Identifies entities needing relationship extraction
- ✅ Creates comprehensive merged JSON files

**Output:**

```
merged_final/
├── _merge_summary.json               # Processing statistics
├── all_documents_consolidated.json   # Single file with all documents
├── Andariel_merged.json             # Individual merged files
├── APT28_merged.json
└── ... (one per document)
```

### Step 3: Analyze Results (Optional)

```bash
python analyze_results.py
```

Provides:

- Statistics and summaries
- Knowledge graph construction
- Query utilities
- Neo4j export format

### Step 4: Visualize (Optional)

```bash
python visualize_results.py
```

Creates:

- Entity distribution charts
- Relation distribution charts
- Network graphs

## 📊 Output Format

### Merged JSON Structure

Each `<document>_merged.json` contains:

```json
{
  "document_name": "APT28.txt",
  "entities": {
    "summary": { /* counts and statistics */ },
    "detailed_list": [ /* all entities with metadata */ ],
    "by_type": { /* entities grouped by type */ }
  },
  "attack_ttps": {
    "tactics": [...],
    "techniques": [...]
  },
  "ioc_indicators": {
    "urls": [], "domains": [], "ips": [],
    "hashes": [], "cves": []
  },
  "relationships": {
    "summary": { /* relation statistics */ },
    "validated_relations": [ /* validated relations only */ ],
    "entities_needing_relationship_extraction": [ /* entities without relations */ ]
  }
}
```

### Consolidated JSON

`all_documents_consolidated.json` contains all 49 documents in a single file for easy querying.

## 🎯 Key Features

### Entity Validation Rules

1. **Rule 1:** Entity in entity extraction but NOT in relationships

   - ✅ Include in output
   - 🔍 Flag for relationship extraction

2. **Rule 2:** Entity in relationships but NOT in entity extraction
   - ❌ Reject the relationship
   - Prevents noisy extractions

### Relationship Filtering

- ✅ Only keeps relations with validated entities
- 🧹 Cleans entity text (removes artifacts like "has", "is", punctuation)
- 🔍 Uses fuzzy matching for entity validation
- 📝 Preserves sentence context
- 🗑️ Removes duplicates

### Comprehensive Data

- All entity types from entity extraction model
- IOC indicators (IPs, domains, hashes, CVEs)
- Knowledge base matches (canonical names, external IDs)
- MITRE ATT&CK tactics and techniques
- Validated relationships with context
- Missing entity identification

## 📈 Use Cases

### 1. Knowledge Graph Construction

```python
import json

with open('merged_final/all_documents_consolidated.json') as f:
    data = json.load(f)

# Build graph
for doc_name, doc_data in data['documents'].items():
    for rel in doc_data['relationships']['validated_relations']:
        graph.add_edge(
            rel['head'],
            rel['tail'],
            relation=rel['relation']
        )
```

### 2. Threat Intelligence Analysis

```python
# Find all tools used by APT28
with open('merged_final/APT28_merged.json') as f:
    apt28 = json.load(f)

tools = [r['tail'] for r in apt28['relationships']['validated_relations']
         if r['relation'] == 'uses' and r['tail_type'] == 'Tool']

print(f"APT28 uses {len(tools)} tools: {tools}")
```

### 3. LLM Integration

```python
# Extract relationships for missing entities
missing = doc_data['relationships']['entities_needing_relationship_extraction']

prompt = f"""
Extract relationships for these entities in {doc_name}:
{', '.join(missing)}

Context: {doc_data['entities']['by_type']}
"""
```

### 4. IOC Extraction

```python
# Get all IOCs for a threat actor
iocs = doc_data['ioc_indicators']
print(f"IPs: {iocs['ips']}")
print(f"Domains: {iocs['domains']}")
print(f"Hashes: {iocs['hashes']}")
print(f"CVEs: {iocs['cves']}")
```

### 5. MITRE ATT&CK Mapping

```python
# Get TTPs
ttps = doc_data['attack_ttps']
for technique in ttps['techniques']:
    print(f"{technique['code']}: {technique['name']}")
```

## 🔧 Troubleshooting

### Issue: Path errors in merged files

The script automatically fixes incorrect paths:

- `/Users/khanhamza/STIXnet/` → `./results/`

### Issue: Missing relationship files

Ensure filename mapping is correct:

- `results/merged/APT28.txt.json` → `relationship/APT28_results.json`

### Issue: Too many/few relations

Adjust validation parameters in `merge_entity_relationship_data.py`:

- `min_length` - Minimum entity text length
- `is_valid_entity()` - Entity validation logic

## 📚 Documentation

- **MERGE_DOCUMENTATION.md** - Detailed merge process explanation
- **README_DOCUMENT_PROCESSING.md** - Relationship extraction details
- **QUICKSTART.md** - Step-by-step execution guide
- **IMPLEMENTATION_SUMMARY.md** - Technical implementation details

## 🎉 Quick Start

**Just run this:**

```bash
python merge_entity_relationship_data.py
```

**Then check:**

```
merged_final/all_documents_consolidated.json
```

This single file contains everything - all entities, relationships, IOCs, and TTPs from all 49 documents! 🚀

## 📊 Expected Results

After running the merger:

- ✅ 49 individual merged JSON files
- ✅ 1 consolidated JSON with all documents
- ✅ ~40-50 entities per document (validated)
- ✅ ~10-20 relationships per document (validated)
- ✅ Full IOC and TTP coverage
- ✅ Entities flagged for additional relationship extraction

## 🔮 Next Steps

1. **Load into Database** - Import to Neo4j or ArangoDB
2. **LLM Processing** - Extract missing relationships
3. **Visualization** - Create threat intelligence graphs
4. **Analysis** - Query patterns and attribution
5. **Integration** - Connect to SIEM or TIP platforms

---

**Happy Threat Intelligence Processing! 🛡️🔍**
