/**
 * @name Find @PreAuthorize annotations and extract authorization expressions
 * @kind problem
 * @id custom/find-preauthorize
 * @problem.severity recommendation
 */

import java

/**
 * Matches @PreAuthorize annotations from Spring Security
 */
class PreAuthorizeAnnotation extends Annotation {
  PreAuthorizeAnnotation() {
    this.getType().hasQualifiedName("org.springframework.security.access.prepost", "PreAuthorize")
  }

  /** Gets the SpEL expression from the annotation value */
  string getExpression() {
    result = this.getValue("value").(CompileTimeConstantExpr).getStringValue()
  }
}

/**
 * Matches controller methods that might delegate to @PreAuthorize-protected service methods
 */
class ControllerMethod extends Method {
  ControllerMethod() {
    this.getDeclaringType().getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RestController")
  }
}

from Method m, PreAuthorizeAnnotation annotation, string spelExpr, string className, string methodName
where
  annotation = m.getAnAnnotation() and
  spelExpr = annotation.getExpression() and
  className = m.getDeclaringType().getName() and
  methodName = m.getName()
select m,
  "Method: " + className + "." + methodName + "() | " +
  "Expression: " + spelExpr + " | " +
  "at " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine()
