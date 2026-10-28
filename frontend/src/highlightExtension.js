
import { StateEffect, StateField } from "@codemirror/state";
import { Decoration, EditorView } from "@codemirror/view";

export const setUnsafeRangesEffect = StateEffect.define();

const unsafeMark = Decoration.mark({
  class: "sqlguard-unsafe-highlight",
});

export const unsafeHighlightField = StateField.define({
  create() {
    return Decoration.none;
  },

  update(decorations, transaction) {
    for (const effect of transaction.effects) {
      if (effect.is(setUnsafeRangesEffect)) {
        const ranges = effect.value
          .filter(
            (range) =>
              Number.isInteger(range.start_offset) &&
              Number.isInteger(range.end_offset) &&
              range.start_offset >= 0 &&
              range.end_offset > range.start_offset &&
              range.end_offset <= transaction.newDoc.length
          )
          .sort((a, b) => a.start_offset - b.start_offset);

        const builder = [];

        for (const range of ranges) {
          builder.push({
            from: range.start_offset,
            to: range.end_offset,
          });
        }

        return Decoration.set(
          builder.map((range) =>
            unsafeMark.range(range.from, range.to)
          ),
          true
        );
      }
    }

    return decorations.map(transaction.changes);
  },

  provide: (field) =>
    EditorView.decorations.from(field),
});

export const unsafeHighlightTheme = EditorView.baseTheme({
  ".sqlguard-unsafe-highlight": {
    backgroundColor: "rgba(239, 68, 68, 0.22)",
    borderBottom: "2px solid #ef4444",
    borderRadius: "2px",
  },
});
