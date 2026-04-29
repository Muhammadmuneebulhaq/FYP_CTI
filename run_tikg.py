"""
TIKG Model for Relationship Extraction
Threat Intelligence Knowledge Graph extraction for CTI documents
"""

import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
import json
import os
from pathlib import Path


# --- 1. RELATION MAPPING ---
def load_relation_mappings(tikg_model_path):
    """Load relation2id and id2relation mappings from TIKG model."""
    relation2id_path = os.path.join(tikg_model_path, "relation2id.txt")
    relation2id = {}
    id2relation = {}
    
    with open(relation2id_path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) == 2:
                relation_name, relation_id = parts[0], int(parts[1])
                relation2id[relation_name] = relation_id
                id2relation[relation_id] = relation_name
    
    return relation2id, id2relation


# --- 2. MODEL CLASS ---
class TIKGRelationExtractor(nn.Module):
    """
    TIKG-based Relation Extraction Model
    Uses SecureBERT for threat intelligence knowledge graph extraction
    """
    def __init__(self, pretrained_model, num_relations):
        super(TIKGRelationExtractor, self).__init__()
        self.bert = pretrained_model
        self.hidden_size = pretrained_model.config.hidden_size
        self.num_relations = num_relations
        
        # Relation classification head
        self.dropout = nn.Dropout(0.1)
        self.rel_classifier = nn.Linear(self.hidden_size * 2, num_relations)
    
    def forward(self, input_ids, attention_mask, head_start, head_end, tail_start, tail_end):
        """
        Forward pass for relation extraction
        
        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            head_start, head_end, tail_start, tail_end: Entity span positions [batch]
        
        Returns:
            logits: Relation classification logits [batch, num_relations]
        """
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        sequence_output = outputs[0]  # [batch, seq_len, hidden_size]
        
        # Extract entity representations (average pooling over span)
        batch_size = sequence_output.size(0)
        head_reps = []
        tail_reps = []
        
        for b in range(batch_size):
            # Head entity representation
            head_span = sequence_output[b, head_start[b]:head_end[b]+1, :]  # [span_len, hidden]
            head_rep = head_span.mean(dim=0)  # [hidden_size]
            head_reps.append(head_rep)
            
            # Tail entity representation
            tail_span = sequence_output[b, tail_start[b]:tail_end[b]+1, :]  # [span_len, hidden]
            tail_rep = tail_span.mean(dim=0)  # [hidden_size]
            tail_reps.append(tail_rep)
        
        # Concatenate head and tail representations
        head_reps = torch.stack(head_reps)  # [batch, hidden_size]
        tail_reps = torch.stack(tail_reps)  # [batch, hidden_size]
        pair_reps = torch.cat([head_reps, tail_reps], dim=1)  # [batch, hidden_size*2]
        
        # Classify relation
        pair_reps = self.dropout(pair_reps)
        logits = self.rel_classifier(pair_reps)  # [batch, num_relations]
        
        return logits


# --- 3. ENTITY EXTRACTION (Simple Greedy NER using keywords) ---
def extract_entities_simple(text, entity_keywords=None):
    """
    Simple entity extraction using keyword matching.
    In production, this could use a pre-trained NER model.
    
    Args:
        text: Input text
        entity_keywords: Dictionary of entity types and their keywords
    
    Returns:
        List of entities with (text, type, start_idx, end_idx)
    """
    if entity_keywords is None:
        # Default cyber threat intelligence entity types and keywords
        entity_keywords = {
            'THREAT_ACTOR': ['APT', 'actor', 'group', 'threat group', 'hacker', 'attacker'],
            'MALWARE': ['malware', 'trojan', 'ransomware', 'backdoor', 'virus', 'worm'],
            'ATTACK': ['attack', 'campaign', 'targeted', 'compromised', 'breach'],
            'TOOL': ['tool', 'scanner', 'exploit', 'utility'],
            'ORGANIZATION': ['organization', 'company', 'agency', 'vendor', 'sector'],
            'INFRASTRUCTURE': ['server', 'domain', 'IP', 'network', 'infrastructure'],
            'CVE': ['CVE-', 'vulnerability', 'exploit'],
        }
    
    entities = []
    text_lower = text.lower()
    
    for entity_type, keywords in entity_keywords.items():
        for keyword in keywords:
            keyword_lower = keyword.lower()
            start = 0
            while True:
                pos = text_lower.find(keyword_lower, start)
                if pos == -1:
                    break
                
                # Extract entity (word boundary handling)
                end = pos + len(keyword)
                # Expand to word boundary
                while end < len(text) and text[end].isalnum():
                    end += 1
                
                entity_text = text[pos:end].strip()
                entities.append({
                    'text': entity_text,
                    'type': entity_type,
                    'start': pos,
                    'end': end
                })
                
                start = end
    
    # Remove duplicates by merging overlapping entities
    entities = sorted(entities, key=lambda x: x['start'])
    merged_entities = []
    
    for ent in entities:
        if merged_entities and ent['start'] < merged_entities[-1]['end']:
            # Overlapping, skip or merge
            continue
        merged_entities.append(ent)
    
    return merged_entities


# --- 4. MODEL LOADING ---
def load_tikg_model(tikg_model_path, device='cpu'):
    """
    Load TIKG model from directory
    
    Args:
        tikg_model_path: Path to TIKG model directory
        device: Device to load model on ('cpu' or 'cuda')
    
    Returns:
        model, tokenizer, relation2id, id2relation
    """
    print(f"Loading TIKG model from {tikg_model_path}...")
    
    # Load tokenizer and pretrained model
    tokenizer_path = os.path.join(tikg_model_path, "my_model_directory")
    model_path = os.path.join(tikg_model_path, "my_model_directory")
    
    try:
        print(f"Loading tokenizer from {tokenizer_path}...")
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        print(f"Loading model from {model_path}...")
        bert_model = AutoModel.from_pretrained(model_path)
        print("[OK] Model and tokenizer loaded from TIKG directory")
    except Exception as e:
        print(f"[WARN] Error loading model from {model_path}: {e}")
        print("[WARN] Falling back to SecureBERT from HuggingFace...")
        try:
            tokenizer = AutoTokenizer.from_pretrained("ehsanaghaei/SecureBERT")
            bert_model = AutoModel.from_pretrained("ehsanaghaei/SecureBERT")
            print("[OK] Loaded SecureBERT fallback model")
        except Exception as e2:
            print(f"[FAIL] Could not load SecureBERT: {e2}")
            raise
    
    # Load relation mappings
    relation2id, id2relation = load_relation_mappings(tikg_model_path)
    num_relations = len(id2relation)
    print(f"[OK] Loaded {num_relations} relation types")
    
    # Create TIKG extractor
    model = TIKGRelationExtractor(bert_model, num_relations)
    
    # Try to load weights
    weights_path = os.path.join(tikg_model_path, "model.pt")
    if os.path.exists(weights_path):
        try:
            print(f"Loading weights from {weights_path}...")
            checkpoint = torch.load(weights_path, map_location=device)
            
            # Handle different checkpoint formats
            if isinstance(checkpoint, dict):
                if 'model_state_dict' in checkpoint:
                    state_dict = checkpoint['model_state_dict']
                elif 'state_dict' in checkpoint:
                    state_dict = checkpoint['state_dict']
                else:
                    state_dict = checkpoint
            else:
                state_dict = checkpoint
            
            # Try to load with strict=False to allow architecture mismatches
            model.load_state_dict(state_dict, strict=False)
            print("[OK] Loaded pre-trained TIKG weights (architecture-agnostic)")
        except Exception as e:
            print(f"[WARN] Could not load weights: {e}")
            print("[WARN] Using default initialization")
    else:
        print(f"[WARN] model.pt not found at {weights_path}")
        print("[WARN] Using default initialization")
    
    model.to(device)
    model.eval()
    print("[OK] Model ready for inference")
    
    return model, tokenizer, relation2id, id2relation


# --- 5. PREDICTION FUNCTION ---
def predict_tikg(text, model, tokenizer, relation2id, id2relation, device='cpu', 
                  confidence_threshold=0.3, debug=False):
    """
    Extract entities and relations from text using TIKG model
    
    Args:
        text: Input text
        model: TIKG model
        tokenizer: Tokenizer
        relation2id: Relation ID mapping
        id2relation: Inverse relation ID mapping
        device: Torch device
        confidence_threshold: Confidence threshold for relations
        debug: Enable debug output
    
    Returns:
        entities: List of extracted entities
        relations: List of extracted relations
    """
    # Extract entities using keyword-based approach
    # In a full implementation, you could use a separate NER model
    entities = extract_entities_simple(text)
    
    if debug:
        print(f"\n=== EXTRACTED ENTITIES ({len(entities)}) ===")
        for i, ent in enumerate(entities, 1):
            print(f"  [{i}] {ent['text']:<30} | Type: {ent['type']:<15} | Span: {ent['start']}-{ent['end']}")
    
    # Tokenize text
    inputs = tokenizer(
        text,
        return_tensors="pt",
        max_length=512,
        truncation=True,
        padding="max_length",
        return_offsets_mapping=True
    )
    
    input_ids = inputs["input_ids"].to(device)
    attention_mask = inputs["attention_mask"].to(device)
    offset_mapping = inputs["offset_mapping"][0].cpu().numpy()
    
    # Map character positions to token positions
    char_to_token = {}
    for token_idx, (start_char, end_char) in enumerate(offset_mapping):
        for char_idx in range(start_char, end_char):
            char_to_token[char_idx] = token_idx
    
    # Extract relations between entity pairs
    relations = []
    
    for i in range(len(entities)):
        for j in range(len(entities)):
            if i == j:
                continue
            
            head_ent = entities[i]
            tail_ent = entities[j]
            
            # Get token positions
            head_start_char = head_ent['start']
            head_end_char = head_ent['end']
            tail_start_char = tail_ent['start']
            tail_end_char = tail_ent['end']
            
            # Map to token positions
            head_start_token = char_to_token.get(head_start_char, 0)
            head_end_token = char_to_token.get(head_end_char - 1, head_start_token)
            tail_start_token = char_to_token.get(tail_start_char, 0)
            tail_end_token = char_to_token.get(tail_end_char - 1, tail_start_token)
            
            # Clamp to valid range
            seq_len = input_ids.size(1)
            head_start_token = min(max(head_start_token, 0), seq_len - 1)
            head_end_token = min(max(head_end_token, 0), seq_len - 1)
            tail_start_token = min(max(tail_start_token, 0), seq_len - 1)
            tail_end_token = min(max(tail_end_token, 0), seq_len - 1)
            
            # Prepare batch inputs
            batch_head_start = torch.tensor([head_start_token], device=device)
            batch_head_end = torch.tensor([head_end_token], device=device)
            batch_tail_start = torch.tensor([tail_start_token], device=device)
            batch_tail_end = torch.tensor([tail_end_token], device=device)
            
            # Get relation prediction
            with torch.no_grad():
                logits = model(
                    input_ids, attention_mask,
                    batch_head_start, batch_head_end,
                    batch_tail_start, batch_tail_end
                )
                
                probs = torch.softmax(logits, dim=1)
                confidence, pred_rel_id = torch.max(probs, dim=1)
                confidence = confidence.item()
                pred_rel_id = pred_rel_id.item()
            
            # Get relation name
            rel_name = id2relation.get(pred_rel_id, '<PAD>')
            
            # Filter by confidence and exclude no-relation class
            if rel_name != '<PAD>' and confidence >= confidence_threshold:
                relations.append({
                    'head': head_ent['text'],
                    'head_type': head_ent['type'],
                    'relation': rel_name,
                    'tail': tail_ent['text'],
                    'tail_type': tail_ent['type'],
                    'confidence': confidence
                })
                
                if debug:
                    print(f"\n  Relation: {head_ent['text']} --[{rel_name}]--> {tail_ent['text']} (conf: {confidence:.3f})")
    
    if debug:
        print(f"\n=== EXTRACTED RELATIONS ({len(relations)}) ===")
        for i, rel in enumerate(relations, 1):
            print(f"  [{i}] {rel['head']:<25} --[{rel['relation']}]--> {rel['tail']} (conf: {rel['confidence']:.3f})")
    
    return entities, relations


# --- 6. TESTING ---
if __name__ == "__main__":
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Using device: {device}\n")
    
    # Load model
    TIKG_MODEL_PATH = "./TIKG_model"
    model, tokenizer, relation2id, id2relation = load_tikg_model(TIKG_MODEL_PATH, device=device)
    
    # Test text
    test_text = "APT28, also known as Fancy Bear, is a Russian state-sponsored threat group. They use malware like Sofacy for targeted attacks. The group operates from Moscow and targets government agencies."
    
    # Extract
    entities, relations = predict_tikg(
        test_text, model, tokenizer, relation2id, id2relation,
        device=device, debug=True
    )
    
    print("\n" + "="*80)
    print("FINAL RESULTS")
    print("="*80)
    print(f"Entities found: {len(entities)}")
    print(f"Relations found: {len(relations)}")
