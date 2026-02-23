/**
 * @name Find authorization checks in FideliusRoleService
 * @kind problem
 * @id custom/find-role-checks
 * @problem.severity recommendation
 */

import java

/**
 * The FideliusRoleService class that contains authorization logic
 */
class FideliusRoleService extends Class {
  FideliusRoleService() {
    this.hasQualifiedName("org.finra.fidelius.services.auth", "FideliusRoleService")
  }
}

/**
 * Authorization check methods in FideliusRoleService
 */
class AuthorizationMethod extends Method {
  AuthorizationMethod() {
    this.getDeclaringType() instanceof FideliusRoleService and
    (
      this.getName().matches("isAuthorized%") or
      this.getName().matches("getRole%") or
      this.getName() = "getRole"
    )
  }
}

/**
 * Calls to authorization methods
 */
from MethodCall call, AuthorizationMethod targetMethod, Method caller, string params
where
  call.getMethod() = targetMethod and
  call.getEnclosingCallable() = caller and
  // Try to extract parameter info
  if call.getNumArgument() = 0 then
    params = "no args"
  else if call.getNumArgument() = 1 then
    params = "1 arg: " + call.getArgument(0).toString()
  else if call.getNumArgument() = 2 then
    params = "2 args: " + call.getArgument(0).toString() + ", " + call.getArgument(1).toString()
  else if call.getNumArgument() = 3 then
    params = "3 args: " + call.getArgument(0).toString() + ", " + call.getArgument(1).toString() + ", " + call.getArgument(2).toString()
  else
    params = call.getNumArgument() + " args"
select call,
  "Caller: " + caller.getDeclaringType().getName() + "." + caller.getName() + "() | " +
  "Calls: FideliusRoleService." + targetMethod.getName() + "(" + params + ") | " +
  "at " + call.getLocation().getFile().getBaseName() + ":" + call.getLocation().getStartLine()
