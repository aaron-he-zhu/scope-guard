# Architecture

## Core idea

Work Contract OS separates agentic work into layers:

```text
User Intent
   ↓
Protocol Layer
   ↓
Task Contract
   ↓
Adapter
   ↓
Specialized Skill
   ↓
Structured Downstream Result
```

## Layers

### 1. Protocol layer
Normalizes intent, surfaces assumptions, determines risk, and inserts approval boundaries.

### 2. Shared contract layer
Represents work as a portable structure rather than raw natural language.

### 3. Adapter layer
Maps the shared contract into a skill-specific workflow while preserving constraints.

### 4. Specialized execution layer
Performs the actual work: document, research, action, coding, and so on.

### 5. Result layer
Returns outputs in a structured shape that can be chained onward.

## Design properties

- composable
- inspectable
- approval-aware
- scope-preserving
- adapter-friendly
