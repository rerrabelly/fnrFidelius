/**
 * @name Call graph for GET /accounts endpoint
 * @description Traces all method calls reachable from FideliusController.getAccounts(),
 *              showing the full call chain with depth, declaring class, file and line number.
 * @kind problem
 * @problem.severity recommendation
 * @id custom/accounts-endpoint-call-graph
 * @tags spring
 *       call-graph
 *       lifecycle
 */

import java

/**
 * Gets the entry-point method: FideliusController.getAccounts()
 */
Method getEntryPoint() {
  result.getName() = "getAccounts" and
  result.getDeclaringType().getName() = "FideliusController"
}

/**
 * Holds if `caller` calls `callee` within the project source (org.finra.fidelius).
 */
predicate projectCall(Method caller, Method callee) {
  exists(MethodCall mc |
    mc.getEnclosingCallable() = caller and
    mc.getMethod() = callee
  ) and
  callee.getDeclaringType().getPackage().getName().matches("org.finra.fidelius%")
}

/**
 * Holds if `m` is reachable from the entry point at the given depth.
 */
predicate reachable(Method m, int depth) {
  m = getEntryPoint() and depth = 0
  or
  exists(Method caller, int d |
    reachable(caller, d) and
    d < 10 and
    projectCall(caller, m) and
    depth = d + 1
  )
}

from Method m, int depth
where reachable(m, depth)
select m,
  "depth=" + depth.toString() +
  " | " + m.getDeclaringType().getName() + "." + m.getName() + "()" +
  " | " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine().toString() +
  " | return=" + m.getReturnType().getName()
