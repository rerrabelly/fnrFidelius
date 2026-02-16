/**
 * @name Find HTTP GET Endpoints
 * @description Finds all HTTP GET endpoint methods in Spring Boot controllers
 * @kind problem
 * @problem.severity recommendation
 * @id java/find-get-endpoints
 */

import java

from Method m, Annotation ann
where
  (
    // Find @GetMapping annotations
    ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping")
    or
    // Find @RequestMapping with GET method
    (
      ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") and
      exists(Expr methodAttr |
        methodAttr = ann.getValue("method") and
        methodAttr.toString().matches("%GET%")
      )
    )
  )
  and ann = m.getAnAnnotation()
select m,
  "GET endpoint: " + m.getDeclaringType().getName() + "." + m.getName() +
  " at " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine()
