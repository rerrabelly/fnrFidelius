/**
 * @name Find all GET endpoints
 * @description Finds all methods annotated with @GetMapping or @RequestMapping(method = GET)
 *              in Spring controllers, including their URL paths, parameters, and return types.
 * @kind problem
 * @problem.severity recommendation
 * @id custom/find-get-endpoints
 * @tags spring
 *       web
 *       endpoints
 */

import java

/**
 * Holds if `a` is a Spring @GetMapping annotation.
 */
predicate isGetMappingAnnotation(Annotation a) {
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping")
}

/**
 * Holds if `a` is a Spring @RequestMapping annotation with method = GET.
 */
predicate isRequestMappingGetAnnotation(Annotation a) {
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") and
  (
    // method = RequestMethod.GET
    exists(Expr methodValue |
      methodValue = a.getValue("method") and
      methodValue.toString().matches("%GET%")
    )
    or
    // @RequestMapping without explicit method defaults to all methods (including GET)
    not exists(a.getValue("method"))
  )
}

/**
 * Gets the URL path from a mapping annotation.
 */
string getPath(Annotation a) {
  // Try "value" first, then "path"
  if exists(a.getValue("value"))
  then result = a.getValue("value").toString()
  else
    if exists(a.getValue("path"))
    then result = a.getValue("path").toString()
    else result = "\"\""
}

/**
 * Gets the class-level @RequestMapping path prefix.
 */
string getClassPath(RefType c) {
  exists(Annotation classMapping |
    classMapping = c.getAnAnnotation() and
    classMapping.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") and
    result = classMapping.getValue("value").toString()
  )
  or
  not exists(Annotation classMapping |
    classMapping = c.getAnAnnotation() and
    classMapping.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")
  ) and
  result = "\"\""
}

/**
 * Holds if `c` is a Spring controller class.
 */
predicate isController(RefType c) {
  c.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RestController")
  or
  c.getAnAnnotation().getType().hasQualifiedName("org.springframework.stereotype", "Controller")
}

from Method m, Annotation a, RefType c, string classPath, string methodPath
where
  (isGetMappingAnnotation(a) or isRequestMappingGetAnnotation(a)) and
  a = m.getAnAnnotation() and
  c = m.getDeclaringType() and
  isController(c) and
  classPath = getClassPath(c) and
  methodPath = getPath(a)
select m,
  "GET endpoint: " + classPath + " + " + methodPath + " | Method: " + m.getName() +
    " | Return: " + m.getReturnType().getName() + " | Class: " + c.getName() +
    " | File: " + m.getLocation().getFile().getBaseName()
