# Adoption Guide

## Smallest useful adoption path

If you want to try this pattern without rebuilding your whole system:

### Step 1
Adopt the task contract schema.

### Step 2
Add a protocol layer, even if it is lightweight.

### Step 3
Pick one downstream workflow and create one adapter for it.

### Step 4
Preserve `approval_required` in every action-oriented flow.

### Step 5
Return structured downstream results instead of plain blobs.

## Recommended first workflows
- memo drafting
- structured summarization
- review → draft → approval flows
- email drafting before send
- code review before patch approval

## What not to do first
- do not try to standardize every skill at once
- do not expose all internal protocol steps to users
- do not start with the highest-risk action flows only
- do not skip examples and validation
