import json
import csv
import os

def run_evaluation():
    # Load dataset labels
    with open('dataset/labels.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        dataset = list(reader)

    # Load Bandit raw results
    with open('results/bandit/bandit_raw.json', 'r', encoding='utf-8') as f:
        bandit_data = json.load(f)

    # Load Semgrep raw results
    with open('results/semgrep/semgrep_raw.json', 'r', encoding='utf-8') as f:
        semgrep_data = json.load(f)

    # Map flagged files
    bandit_flagged = set()
    bandit_details = {}
    for r in bandit_data.get('results', []):
        fn = r['filename'].replace('\\', '/')
        if fn.startswith('dataset/'):
            fn = fn[len('dataset/'):]
        bandit_flagged.add(fn)
        bandit_details.setdefault(fn, []).append({
            'test_id': r.get('test_id'),
            'issue_text': r.get('issue_text'),
            'line_number': r.get('line_number')
        })

    semgrep_flagged = set()
    semgrep_details = {}
    for r in semgrep_data.get('results', []):
        fn = r['path'].replace('\\', '/')
        if fn.startswith('dataset/'):
            fn = fn[len('dataset/'):]
        semgrep_flagged.add(fn)
        semgrep_details.setdefault(fn, []).append({
            'check_id': r.get('check_id'),
            'line_number': r.get('start', {}).get('line')
        })

    # Prepare comparison records
    records = []
    for row in dataset:
        fn = row['file']
        expected = row['label']
        b_flagged = fn in bandit_flagged
        s_flagged = fn in semgrep_flagged

        # Recording exact result produced by the tool
        b_res = 'vulnerable' if b_flagged else 'safe'
        s_res = 'vulnerable' if s_flagged else 'safe'

        records.append({
            'filename': fn,
            'expected_label': expected,
            'bandit_result': b_res,
            'semgrep_result': s_res,
            'bandit_flagged': b_flagged,
            'semgrep_flagged': s_flagged
        })

    # Write summary CSV
    csv_headers = ['filename', 'expected_label', 'bandit_result', 'semgrep_result']
    with open('results/summary.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        for rec in records:
            writer.writerow({k: rec[k] for k in csv_headers})

    with open('results/comparison_summary.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        for rec in records:
            writer.writerow({k: rec[k] for k in csv_headers})

    # Calculate metrics
    def compute_metrics(tool_flagged_key):
        tp = sum(1 for r in records if r['expected_label'] == 'unsafe' and r[tool_flagged_key])
        fn = sum(1 for r in records if r['expected_label'] == 'unsafe' and not r[tool_flagged_key])
        
        fp_safe = sum(1 for r in records if r['expected_label'] == 'safe' and r[tool_flagged_key])
        fp_tricky = sum(1 for r in records if r['expected_label'] == 'tricky' and r[tool_flagged_key])
        fp_total = fp_safe + fp_tricky

        tn_safe = sum(1 for r in records if r['expected_label'] == 'safe' and not r[tool_flagged_key])
        tn_tricky = sum(1 for r in records if r['expected_label'] == 'tricky' and not r[tool_flagged_key])
        tn_total = tn_safe + tn_tricky

        precision = tp / (tp + fp_total) if (tp + fp_total) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            'TP': tp,
            'FP': fp_total,
            'FP_breakdown': {'safe': fp_safe, 'tricky': fp_tricky},
            'FN': fn,
            'TN': tn_total,
            'TN_breakdown': {'safe': tn_safe, 'tricky': tn_tricky},
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4)
        }

    bandit_metrics = compute_metrics('bandit_flagged')
    semgrep_metrics = compute_metrics('semgrep_flagged')

    with open('results/bandit/bandit_summary.json', 'w', encoding='utf-8') as f:
        json.dump({
            'tool': 'Bandit 1.9.4',
            'command': 'bandit -r dataset -f json -o results/bandit/bandit_raw.json',
            'metrics': bandit_metrics,
            'details': bandit_details
        }, f, indent=2)

    with open('results/semgrep/semgrep_summary.json', 'w', encoding='utf-8') as f:
        json.dump({
            'tool': 'Semgrep 1.179.0',
            'command': 'semgrep scan --config auto dataset --json -o results/semgrep/semgrep_raw.json',
            'metrics': semgrep_metrics,
            'details': semgrep_details
        }, f, indent=2)

    print('Evaluation completed successfully.')
    print('Bandit metrics:', bandit_metrics)
    print('Semgrep metrics:', semgrep_metrics)

if __name__ == '__main__':
    run_evaluation()
