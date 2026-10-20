# Staff page toolkit

`staff.html` (one level up) is the password-protected staff page. Its content is
encrypted; nothing in this folder contains schedule data.

The staff page is built from the dojang items in the owner's Salt & Light Daily
artifact database (collections `events`, `days`, `tasks`). English text and
include/exclude decisions are remembered inside the encrypted page, so a rebuild
only asks about new or changed items.

## Rebuild

```
pip install cryptography            # if missing
python3 _staff/staffkit.py prepare DUMP_DIR WORK_DIR PASSWORD
# fill in WORK_DIR/pending.json if it lists anything
python3 _staff/staffkit.py build   DUMP_DIR WORK_DIR PASSWORD
```

`build` prints `CHANGED` (commit `staff.html`) or `UNCHANGED` (nothing to do).

## Deciding pending items

- Include only dojang items: classes, class changes, belt tests, tournaments,
  camps, community events, dojang prep steps and checklists.
- Exclude personal items: church, family, friends, meals, medical, personal
  travel and personal calls.
- Translate Korean to short, plain English in the same style as existing items
  (for example "Belt Testing prep starts (4 weeks before)", "Print checklist",
  "Give out tapes").
