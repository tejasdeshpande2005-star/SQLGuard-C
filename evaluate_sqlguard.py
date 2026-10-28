"""Evaluate SQLGuard-C prototype against dataset/labels.csv (unsafe vs not-unsafe)."""
import csv
from sqlguard.analysis.taint import analyze_file

def main():
    with open('dataset/labels.csv',newline='',encoding='utf-8') as f: rows=list(csv.DictReader(f))
    tp=fp=fn=tn=0
    for row in rows:
        predicted=bool(analyze_file('dataset/'+row['file']))
        actual=row['label']=='unsafe'
        if actual and predicted: tp+=1
        elif actual and not predicted: fn+=1
        elif not actual and predicted: fp+=1
        else: tn+=1
        print(f"{'FLAG' if predicted else 'CLEAN':5} expected={row['label']:6} {row['file']}")
    precision=tp/(tp+fp) if tp+fp else 0
    recall=tp/(tp+fn) if tp+fn else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    print(f'\nTP={tp} FP={fp} FN={fn} TN={tn}')
    print(f'Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}')
    print('Note: tiny hand-labelled demo dataset; these metrics are not a general security guarantee.')
if __name__=='__main__': main()
