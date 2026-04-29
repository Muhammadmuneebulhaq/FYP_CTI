import streamlit as st
import streamlit.components.v1 as components
import os
import shutil
import subprocess
import json
import glob
import sys

# Document processing: text/image extraction from PDF and Word files
from document_processor import process_document

# Configuration
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT_DIR, "Data")
BACKUP_DIR = os.path.join(ROOT_DIR, "Data_Backup")
RESULTS_DIR = os.path.join(ROOT_DIR, "results")
MERGED_DIR = os.path.join(ROOT_DIR, "merged_final")
VALIDATED_DIR = os.path.join(ROOT_DIR, "validated_stix")
# Temporary directory for images extracted from uploaded documents
IMAGES_DIR = os.path.join(ROOT_DIR, "extracted_images")
PYTHON_EXEC = sys.executable

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MERGED_DIR, exist_ok=True)
os.makedirs(VALIDATED_DIR, exist_ok=True)
os.makedirs(IMAGES_DIR, exist_ok=True)

def backup_data():
    """Move existing files from Data to Data_Backup to isolate the single input."""
    files = glob.glob(os.path.join(DATA_DIR, "*"))
    for f in files:
        shutil.move(f, os.path.join(BACKUP_DIR, os.path.basename(f)))

def restore_data():
    """Restore files from Data_Backup to Data."""
    # First, clear any temporary files in Data
    files = glob.glob(os.path.join(DATA_DIR, "*"))
    for f in files:
        os.remove(f)
    
    # Move backup files back
    files = glob.glob(os.path.join(BACKUP_DIR, "*"))
    for f in files:
        shutil.move(f, os.path.join(DATA_DIR, os.path.basename(f)))

def run_script(script_name, description):
    """Run a python script and return success status."""
    st.write(f"running {description}...")
    try:
        # Increase timeout to 30 minutes (1800 seconds) for long-running tasks like IOC extraction
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        result = subprocess.run(
            [PYTHON_EXEC, script_name],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            encoding='utf-8',
            env=env,
            timeout=1800
        )
        if result.returncode != 0:
            st.error(f"Failed: {description}")
            st.write("**STDERR Output:**")
            st.code(result.stderr)
            if result.stdout:
                st.write("**STDOUT Output:**")
                st.code(result.stdout)
            return False
        return True
    except subprocess.TimeoutExpired:
        st.error(f"Timeout: {description} took longer than 30 minutes")
        return False
    except Exception as e:
        st.error(f"Error running {description}: {e}")
        return False

def _read_js_file(path):
    """Read a JS file and return its contents as a string."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _build_icon_map():
    """Build a dict of STIX type -> base64 data URI for all available icons."""
    import base64
    icons_dir = os.path.join(ROOT_DIR, "stix2viz", "stix2viz", "icons")
    stix_types = [
        "artifact", "attack-pattern", "autonomous-system", "bundle",
        "campaign", "course-of-action", "directory", "domain-name",
        "email-addr", "email-message", "event", "file", "grouping",
        "identity", "impact", "incident", "indicator", "infrastructure",
        "intrusion-set", "ipv4-addr", "ipv6-addr", "location",
        "mac-addr", "malware", "malware-analysis", "marking-definition",
        "mutex", "network-traffic", "note", "observed-data", "opinion",
        "process", "relationship", "report", "sighting", "software",
        "task", "threat-actor", "tool", "url", "user-account",
        "vulnerability", "windows-registry-key", "x509-certificate",
        "data-component",
    ]
    icon_map = {}
    for t in stix_types:
        fname = f"stix2_{t.replace('-', '_')}_icon_tiny_round_v1.png"
        fpath = os.path.join(icons_dir, fname)
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            icon_map[t] = f"data:image/png;base64,{data}"
    # SVG fallback for custom/unknown types
    fallback = os.path.join(icons_dir, "stix2_custom_object_icon_tiny_round_v1.svg")
    if os.path.exists(fallback):
        with open(fallback, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        icon_map["__fallback__"] = f"data:image/svg+xml;base64,{data}"
    return icon_map


def render_stix_visualization(json_data):
    """
    Render a STIX 2.x bundle as an interactive graph.

    Uses vis-network (inlined as minified JS) with STIX icons embedded
    as base64 data URIs — no external file access needed inside the
    sandboxed Streamlit iframe.
    """
    is_bundle = (
        json_data.get("type") == "bundle"
        and "objects" in json_data
        and len(json_data["objects"]) > 0
    )
    if not is_bundle:
        st.info(
            "ℹ️ The current output is in an intermediate (pre-validation) format "
            "and cannot be rendered as a STIX graph. Run with **LLM Validation enabled** "
            "to produce a STIX 2.1 Bundle that the visualizer can render."
        )
        st.json(json_data)
        return

    vis_js_path = os.path.join(ROOT_DIR, "stix2viz", "visjs", "vis-network.min.js")
    try:
        vis_js = _read_js_file(vis_js_path)
    except FileNotFoundError:
        st.error("vis-network.min.js not found. Check stix2viz/visjs/ directory.")
        return

    icon_map = _build_icon_map()
    stix_json_str = json.dumps(json_data)
    icon_map_str  = json.dumps(icon_map)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box;}}
    body{{background:#1e1e2e;color:#cdd6f4;font-family:Arial,sans-serif;}}
    #graph-wrap{{width:100%;height:490px;border:2px solid #45475a;border-radius:8px;background:#181825;}}
    #detail{{margin-top:6px;padding:8px 12px;background:#181825;border:1px solid #45475a;
             border-radius:6px;font-size:11px;line-height:1.7;max-height:190px;
             overflow-y:auto;display:none;white-space:pre-wrap;word-break:break-all;}}
    #d-title{{font-size:13px;font-weight:bold;color:#89b4fa;margin-bottom:4px;}}
    .pk{{color:#cba6f7;}}.pv{{color:#a6e3a1;}}
    .info{{font-size:11px;color:#6c7086;padding:3px 0 5px;}}
    #legend{{display:flex;flex-wrap:wrap;gap:6px;padding:4px 0 6px;font-size:11px;color:#bac2de;}}
    .li{{display:flex;align-items:center;gap:3px;}}
    .ld{{width:11px;height:11px;border-radius:50%;flex-shrink:0;}}
  </style>
</head>
<body>
  <div class="info">Drag to pan &bull; Scroll to zoom &bull; Click node for details</div>
  <div id="legend"></div>
  <div id="graph-wrap"></div>
  <div id="detail"><div id="d-title"></div><div id="d-body"></div></div>

<script>{vis_js}</script>
<script>
(function(){{
  var STIX  = {stix_json_str};
  var ICONS = {icon_map_str};

  var COLORS = {{
    "attack-pattern":"#fab387","campaign":"#f38ba8",
    "course-of-action":"#a6e3a1","grouping":"#94e2d5",
    "identity":"#89dceb","incident":"#eba0ac",
    "indicator":"#f9e2af","infrastructure":"#cba6f7",
    "intrusion-set":"#f38ba8","location":"#89dceb",
    "malware":"#f38ba8","malware-analysis":"#fab387",
    "note":"#cdd6f4","observed-data":"#94e2d5",
    "opinion":"#bac2de","report":"#f9e2af",
    "threat-actor":"#f38ba8","tool":"#a6e3a1",
    "vulnerability":"#eba0ac","data-component":"#74c7ec",
    "artifact":"#89b4fa","autonomous-system":"#89b4fa",
    "directory":"#89b4fa","domain-name":"#89b4fa",
    "email-addr":"#89b4fa","email-message":"#89b4fa",
    "file":"#89b4fa","ipv4-addr":"#89b4fa",
    "ipv6-addr":"#89b4fa","mac-addr":"#89b4fa",
    "mutex":"#89b4fa","network-traffic":"#89b4fa",
    "process":"#89b4fa","software":"#89b4fa",
    "url":"#89b4fa","user-account":"#89b4fa",
    "windows-registry-key":"#89b4fa","x509-certificate":"#89b4fa"
  }};
  var DFLT = "#6c7086";

  var objects = STIX.objects || [];
  var lookup  = {{}};
  objects.forEach(function(o){{ if(o.id) lookup[o.id]=o; }});

  var nodes=[], edges=[], usedTypes={{}};
  objects.forEach(function(obj){{
    if(!obj.id||!obj.type) return;
    if(obj.type==="relationship"){{
      if(obj.source_ref&&obj.target_ref)
        edges.push({{
          id:obj.id, from:obj.source_ref, to:obj.target_ref,
          label:obj.relationship_type||"",
          arrows:"to",
          font:{{size:10,color:"#a6adc8",align:"middle"}},
          color:{{color:"#585b70",highlight:"#cba6f7",hover:"#cba6f7"}},
          smooth:{{type:"curvedCW",roundness:0.2}}
        }});
      return;
    }}
    usedTypes[obj.type]=true;
    var lbl = obj.name||obj.value||obj.path||obj.type;
    if(lbl.length>28) lbl=lbl.substr(0,26)+"..";
    var col  = COLORS[obj.type]||DFLT;
    var icon = ICONS[obj.type]||ICONS["__fallback__"]||"";
    nodes.push({{
      id:obj.id, label:lbl, title:obj.type,
      color:{{background:col,border:"#181825",
             highlight:{{background:col,border:"#cdd6f4"}},
             hover:{{background:col,border:"#cdd6f4"}}}},
      font:{{color:"#1e1e2e",size:11,bold:true}},
      shape: icon?"circularImage":"dot",
      image: icon||undefined,
      size:28, borderWidth:2
    }});
  }});

  // Legend
  var leg=document.getElementById("legend");
  Object.keys(usedTypes).forEach(function(t){{
    var c=COLORS[t]||DFLT;
    var el=document.createElement("div");
    el.className="li";
    el.innerHTML='<div class="ld" style="background:'+c+'"></div>'+t;
    leg.appendChild(el);
  }});

  var opts={{
    physics:{{
      enabled:true, solver:"forceAtlas2Based",
      forceAtlas2Based:{{gravitationalConstant:-60,centralGravity:0.008,
                        springLength:140,springConstant:0.05}},
      stabilization:{{iterations:200}}
    }},
    interaction:{{hover:true,tooltipDelay:100,zoomView:true,dragView:true}},
    edges:{{smooth:{{type:"curvedCW",roundness:0.2}},
           font:{{size:10,color:"#a6adc8"}},color:"#585b70"}},
    nodes:{{borderWidth:2}}
  }};

  var net=new vis.Network(
    document.getElementById("graph-wrap"),
    {{nodes:new vis.DataSet(nodes),edges:new vis.DataSet(edges)}},
    opts
  );

  var detail=document.getElementById("detail");
  var dbody =document.getElementById("d-body");
  var dtitle=document.getElementById("d-title");

  net.on("click",function(p){{
    if(p.nodes.length>0){{
      var obj=lookup[p.nodes[0]]; if(!obj) return;
      dtitle.textContent=(obj.name||obj.type)+" ["+obj.type+"]";
      var h="";
      Object.entries(obj).forEach(function(kv){{
        var v=typeof kv[1]==="object"?JSON.stringify(kv[1],null,2):String(kv[1]);
        h+='<div><span class="pk">'+kv[0]+': </span><span class="pv">'+v+'</span></div>';
      }});
      dbody.innerHTML=h; detail.style.display="block";
    }} else detail.style.display="none";
  }});

  net.on("selectEdge",function(p){{
    if(p.edges.length>0){{
      var obj=lookup[p.edges[0]]; if(!obj) return;
      dtitle.textContent="Relationship: "+(obj.relationship_type||obj.id);
      var h="";
      Object.entries(obj).forEach(function(kv){{
        var v=typeof kv[1]==="object"?JSON.stringify(kv[1]):String(kv[1]);
        h+='<div><span class="pk">'+kv[0]+': </span><span class="pv">'+v+'</span></div>';
      }});
      dbody.innerHTML=h; detail.style.display="block";
    }}
  }});
}})();
</script>
</body>
</html>"""

    st.info("🔵 STIX 2.1 Bundle — interactive graph (icons embedded, no external files)")
    components.html(html, height=760, scrolling=False)

# ── Streamlit UI ──────────────────────────────────────────────────────────────
st.set_page_config(page_title="CTI Pipeline", layout="wide")
st.title("🕵️‍♂️ CTI Extraction & STIX Generation Pipeline")

# Session state — persists extracted images and status across Streamlit reruns
if "extracted_images" not in st.session_state:
    st.session_state.extracted_images = []
if "doc_status" not in st.session_state:
    st.session_state.doc_status = None

st.markdown("""
This tool processes raw Cyber Threat Intelligence (CTI) reports to extract entities (Threat Actors, Malware, IOCs, TTPs), 
identifies relationships, and generates STIX 2.1 compatible graphs.
""")

# Sidebar options
st.sidebar.header("Configuration")
enable_llm = st.sidebar.checkbox("Enable LLM Validation", value=False, help="Requires Gemini API Quota")
relation_model = st.sidebar.radio(
    "Relationship Extraction Model",
    options=["TIKG", "TIRE"],
    index=0,
    help="Choose between TIKG (Threat Intelligence Knowledge Graph) or TIRE (Transformer-based Information Relation Extraction)"
)

# ── Input Area ────────────────────────────────────────────────────────────────
st.markdown(
    "Provide a CTI report either by **pasting text** or by **uploading a file**. "
    "If a file is uploaded it takes priority over pasted text."
)

tab_paste, tab_upload = st.tabs(["📝 Paste Text", "📁 Upload Document (PDF / DOC / DOCX)"])

with tab_paste:
    input_text = st.text_area(
        "Paste CTI Report Text Here:",
        height=300,
        help="Paste the raw threat-intelligence report text.",
    )

with tab_upload:
    uploaded_file = st.file_uploader(
        "Upload a PDF or Word document",
        type=["pdf", "doc", "docx"],
        help="Accepted formats: PDF (.pdf), Word 2007+ (.docx), Legacy Word (.doc)",
    )
    if uploaded_file is not None:
        st.success(f"✅ File received: **{uploaded_file.name}** "
                   f"({uploaded_file.size / 1024:.1f} KB)")

if st.button("Run Pipeline"):
    # ── Determine the text source ──────────────────────────────────────────
    # Priority: uploaded file > pasted text
    pipeline_text = ""
    st.session_state.extracted_images = []  # reset on each run
    st.session_state.doc_status = None

    if uploaded_file is not None:
        # ── Extract text (and images) from the uploaded document ──────────
        with st.spinner(f"Extracting content from {uploaded_file.name}…"):
            file_bytes = uploaded_file.read()

            # Clear previous extracted images
            for old_img in glob.glob(os.path.join(IMAGES_DIR, "*")):
                try:
                    os.remove(old_img)
                except OSError:
                    pass

            ext_text, ext_images, ext_status = process_document(
                file_bytes, uploaded_file.name, IMAGES_DIR
            )

        # ── Show extraction summary ────────────────────────────────────────
        st.markdown("**📄 Document Extraction Summary**")
        if ext_status == "OK":
            st.success(
                f"✅ Text extracted successfully — "
                f"{len(ext_text.split())} words · "
                f"{len(ext_images)} image(s) found"
            )
        else:
            st.warning(f"⚠️ Extraction notice: {ext_status}")

        if not ext_text.strip():
            st.error(
                "No usable text could be extracted from the uploaded document. "
                "Cannot run the pipeline."
            )
            st.stop()

        pipeline_text = ext_text
        st.session_state.extracted_images = ext_images
        st.session_state.doc_status = ext_status

    elif input_text.strip():
        # Fall back to manually pasted text
        pipeline_text = input_text

    if not pipeline_text.strip():
        st.warning("Please paste a CTI report or upload a document first.")
        st.stop()

    status_placeholder = st.empty()
    status_placeholder.info("Starting pipeline…")

    # 1. Backup Data
    backup_data()

    try:
        # 2. Save the (cleaned) text so the pipeline scripts can read it
        with open(os.path.join(DATA_DIR, "input.txt"), "w", encoding="utf-8") as f:
            f.write(pipeline_text)

        # 3. Run Pipeline Stages
        progress_bar = st.progress(0)

        # Stage 1: KB Match
        status_placeholder.text("Stage 1/5: Running Knowledge Base Matching...")
        run_script("kb_match_batch.py", "KB Matching")
        progress_bar.progress(20)

        # Stage 2: IOC Extraction
        status_placeholder.text("Stage 2/5: Running IOC Extraction...")
        run_script("run_ioc_extraction.py", "IOC Extraction")
        progress_bar.progress(40)

        # Stage 3: Novel Entity Extraction
        status_placeholder.text("Stage 3/7: Running Novel Entity Extraction...")
        run_script("novel_entities.py", "Novel Entity Extraction")
        progress_bar.progress(40)

        # Stage 4: TTP Extraction
        status_placeholder.text("Stage 4/7: Running TTP Extraction...")
        ttp_script = os.path.join("Entity-Extraction", "rcATT", "infer_rcatt.py")
        run_script(ttp_script, "TTP Extraction")
        progress_bar.progress(55)

        # Stage 5: Entity Merging
        status_placeholder.text("Stage 5/7: Merging Entities...")
        run_script("merge_entities.py", "Entity Merging")
        progress_bar.progress(70)

        # Stage 6: Relationship Extraction
        status_placeholder.text("Stage 6/7: Running Relationship Extraction...")
        if relation_model == "TIKG":
            run_script("process_documents_tikg.py", "Relationship Extraction (TIKG)")
        else:
            run_script("process_documents.py", "Relationship Extraction (TIRE)")
        progress_bar.progress(85)

        # Stage 7: Relationship Fusion
        status_placeholder.text("Stage 7/7: Fusing Relationships...")
        run_script("merge_entity_relationship_data.py", "Data Fusion")
        progress_bar.progress(95)

        # LLM Validation (Optional)
        llm_success = False
        if enable_llm:
            status_placeholder.text("Stage 5/5: Running LLM Validation...")
            merged_file = os.path.join(MERGED_DIR, "input_merged.json")
            text_file   = os.path.join(DATA_DIR, "input.txt")
            output_file = os.path.join(VALIDATED_DIR, "input_stix.json")

            if os.path.exists(merged_file):
                env = os.environ.copy()
                env['PYTHONIOENCODING'] = 'utf-8'
                result = subprocess.run(
                    [PYTHON_EXEC, "LLM_Validation.py",
                     "--json", merged_file, "--text", text_file, "--output", output_file],
                    cwd=ROOT_DIR,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    env=env
                )
                if result.returncode == 0:
                    st.success("LLM Validation Complete")
                    llm_success = True
                else:
                    st.warning(f"LLM Validation Failed (likely rate limit): {result.stderr}")
            else:
                st.error("Merged file not found, skipping LLM.")
        else:
            status_placeholder.text("Skipping LLM Validation (Disabled)")

        progress_bar.progress(100)
        status_placeholder.success("Pipeline Execution Complete!")

        # 4. Display Results
        final_output_path = os.path.join(MERGED_DIR, "input_merged.json")
        if enable_llm and llm_success:
            stix_path = os.path.join(VALIDATED_DIR, "input_stix.json")
            if os.path.exists(stix_path):
                final_output_path = stix_path

        if os.path.exists(final_output_path):
            with open(final_output_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            col1, col2 = st.columns([1, 1])
            with col1:
                st.subheader("Extracted Data (JSON)")
                st.json(data)
            with col2:
                st.subheader("STIX Graph Visualization")
                render_stix_visualization(data)

            # ── Document images ────────────────────────────────────────────
            # Show images extracted from the uploaded file below the graph.
            # Only displayed when a document was uploaded (not plain text).
            doc_images = st.session_state.get("extracted_images", [])
            doc_images = [p for p in doc_images if os.path.isfile(p)]
            if doc_images:
                st.markdown("---")
                st.subheader("Further information in the document")

                st.caption(f"{len(doc_images)} image(s) extracted from the uploaded document.")
                # Vertical stack — one image per row, full width
                for img_path in doc_images:
                    st.image(
                        img_path,
                        caption=os.path.basename(img_path),
                        use_container_width=True,
                    )
        else:
            st.error("No output generated. Check logs.")

    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")

    finally:
        # 5. Restore Data
        restore_data()
