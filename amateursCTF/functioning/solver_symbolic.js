
const fs = require('fs');

// 1. Read the file
const code = fs.readFileSync('chal.js', 'utf8');

// 2. Extract the body of J
const startJ = code.indexOf('const J = (x) =>');
const endJ = code.indexOf('const K =');
const jContent = code.substring(startJ, endJ);

// 3. Setup the symbolic execution environment

// Helper to handle mixed number/symbol operations
const op = (type, x, y) => {
    if (typeof x === 'number' && typeof y === 'number') {
        switch (type) {
            case 'ADD': return x + y;
            case 'MUL': return x * y;
            case 'POW': return x ** y;
            case 'AND': return x & y;
        }
    }
    return { type, left: x, right: y };
};

const a = () => 0;
const b = (x, y) => op('ADD', x, y);
const c = (x, y) => op('MUL', x, y);
const d = (x, y) => op('POW', x, y);
const e = (x, y) => op('AND', x, y);

const constraints = [];

// Hook g: returns a symbol for the character at index y
const g = (x, y) => {
    // y should be a number (the index)
    if (typeof y !== 'number') {
        // If y is symbolic, we have a problem (indirect addressing). 
        // Hopefully indices are static constants.
        console.log("Warning: Symbolic index", y);
    }
    return { type: 'VAR', index: y };
};

// Hook I: records the equality constraint
const I = (val, variable) => {
    // variable should be the result of g(x, idx) -> { type: 'VAR', index: ... }
    constraints.push({ target: variable, expr: val });
    return 0; // Return 0 to satisfy B
};

// Hook B: just returns 0 to keep things moving
const B = (x, y) => 0;

// Hook H: Not used in the constraint generation of I's arguments, 
// but called in the second arg of B. We can stub it.
const H = (x, y) => 0;

// Hook f: Traverse the success path
const f = (cond, fail, success) => {
    // Execute success path to find more constraints
    if (typeof success === 'function') success();
    return 0;
};

// Stub others
const A = () => 0;
const C = () => 0;
const D = () => 0;
const E = () => 0;
const F = () => 0;
const G = () => 0;

// We need to eval the J code in this context.
// We can wrap it in a function or just eval the expression.
// J is defined as `const J = (x) => ...`
// We want to run the body: `f(B(I(...)...`

// Let's clean the J definition to just the body expression
let body = jContent.trim();
if (body.startsWith('const J = (x) =>')) {
    body = body.replace('const J = (x) =>', '');
}
// Remove trailing semicolon if any
body = body.trim();
if (body.endsWith(';')) body = body.slice(0, -1);

// Run it
try {
    eval(body);
} catch (e) {
    console.log("Error executing body:", e);
}

// 4. Solve the constraints
const solution = new Array(100).fill(null);

// Helper to evaluate a symbolic expression given the current solution state
const evaluate = (expr) => {
    if (typeof expr === 'number') return expr;
    if (expr.type === 'VAR') {
        return solution[expr.index]; // might be null
    }
    
    const l = evaluate(expr.left);
    const r = evaluate(expr.right);
    
    if (l === null || r === null) return null;
    
    switch (expr.type) {
        case 'ADD': return l + r;
        case 'MUL': return l * r;
        case 'POW': return l ** r;
        case 'AND': return l & r;
    }
    return null;
};

// Iteratively solve
let changed = true;
while (changed) {
    changed = false;
    for (const constr of constraints) {
        const idx = constr.target.index;
        if (solution[idx] !== null) continue; // already solved
        
        const val = evaluate(constr.expr);
        if (val !== null) {
            solution[idx] = val;
            changed = true;
        }
    }
}

// 5. Output
const flag = solution.map(c => c ? String.fromCharCode(c) : '').join('');
console.log("Constraints found:", constraints.length);
console.log("Flag:", flag);
