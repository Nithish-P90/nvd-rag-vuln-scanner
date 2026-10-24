// agents/joern_cpg/extract_cpg.sc
//
// Run by JoernRunner (one run per language over the whole project root):
//   joern --script extract_cpg.sc
// Inputs come from environment variables, not --param, because the Windows
// joern.bat launcher splits "key=value" arguments on '='.
//   JOERN_INPUT     project root (or single file) to import
//   JOERN_OUT       path of the JSON file to write
//   JOERN_LANGUAGE  frontend key: c | java | js | python | go | php | (empty = autodetect)
//   JOERN_SOURCE_RE / JOERN_SINK_RE  full-match regexes on call code for taint flows (optional)
//   JOERN_FLOW_TIMEOUT               seconds allowed for the taint query (default 120)
//
// Builds ONE CPG covering every matching file under inputPath, then dumps a
// compact JSON summary: methods (with file, params, locals, calls, control
// structures, returns), data-dependence edges (REACHING_DEF), control-
// dependence edges (CDG) and interprocedural source->sink taint flows.
// Cross-file call resolution happens in Python (graph.py), so the validation
// agent can re-extract context without re-running Joern.
//
// Verified against Joern 4.0.654 (Windows CLI build).

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import scala.concurrent.{Await, Future}
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global

def q(s: String): String = {
  if (s == null) "null"
  else "\"" + s.flatMap {
    case '"'  => "\\\""
    case '\\' => "\\\\"
    case '\n' => "\\n"
    case '\r' => "\\r"
    case '\t' => "\\t"
    case c if c < ' ' => "\\u%04x".format(c.toInt)
    case c => c.toString
  } + "\""
}

def arr(items: Seq[String]): String = items.mkString("[", ",", "]")
def num(o: Option[Int]): String = o.map(_.toString).getOrElse("null")

@main def exec(): Unit = {
  val inputPath = sys.env("JOERN_INPUT")
  val outFile   = sys.env("JOERN_OUT")
  val language  = sys.env.getOrElse("JOERN_LANGUAGE", "")

  language match {
    case "c"          => importCode.c(inputPath)
    case "java"       => importCode.java(inputPath)
    case "js"         => importCode.jssrc(inputPath)
    case "python"     => importCode.python(inputPath)
    case "go"         => importCode.golang(inputPath)
    case "php"        => importCode.php(inputPath)
    case _            => importCode(inputPath)
  }
  run.ossdataflow

  // Project methods only. Keep <module> (Python top-level code) and <global>
  // (C/C++ file-level code), which hold statements in scripts. Drop other
  // synthetic names such as <init>, <metaClassAdapter>, <lambda>.
  val keepSynthetic = Set("<module>", "<global>")
  val methods = cpg.method.isExternal(false)
    .filter(m => !m.name.contains("<") || keepSynthetic.contains(m.name)).l

  val methodJson = methods.map { m =>
    val params = m.parameter.l.map(p =>
      s"""{"name":${q(p.name)},"type":${q(p.typeFullName)},"order":${p.order}}""")
    val locals = m.local.l.map(l =>
      s"""{"name":${q(l.name)},"type":${q(l.typeFullName)},"line":${num(l.lineNumber)},"code":${q(l.code)}}""")
    val calls = m.call.l.map(c =>
      s"""{"name":${q(c.name)},"code":${q(c.code)},"line":${num(c.lineNumber)},""" +
      s""""callee":${q(c.methodFullName)},"args":${arr(c.argument.l.map(a => q(a.code)))}}""")
    val controls = m.controlStructure.l.map { cs =>
      val lines = cs.ast.collectAll[CfgNode].lineNumber.l.map(_.toInt)
      val end   = if (lines.isEmpty) "null" else lines.max.toString
      s"""{"type":${q(cs.controlStructureType)},"code":${q(cs.code)},"line":${num(cs.lineNumber)},"end":$end,""" +
      s""""cond":${arr(cs.condition.l.map(c => q(c.code)))}}"""
    }
    val rets = m.ast.isReturn.l.map(r => s"""{"code":${q(r.code)},"line":${num(r.lineNumber)}}""")
    s"""{"file":${q(m.filename)},"name":${q(m.name)},"fullName":${q(m.fullName)},"signature":${q(m.signature)},""" +
    s""""line":${num(m.lineNumber)},"end":${num(m.lineNumberEnd)},""" +
    s""""params":${arr(params)},"locals":${arr(locals)},"calls":${arr(calls)},""" +
    s""""controls":${arr(controls)},"returns":${arr(rets)}}"""
  }

  // Data-dependence edges: [file, methodFullName, fromLine, toLine, variable].
  val ddg = cpg.graph.allEdges.filter(_.label == "REACHING_DEF").l.flatMap { e =>
    (e.src, e.dst) match {
      case (s: CfgNode, d: CfgNode) =>
        (s.lineNumber, d.lineNumber) match {
          case (Some(a), Some(b)) if a != b =>
            val m = s.method
            if (m.isExternal) None
            else Some(s"""[${q(m.filename)},${q(m.fullName)},${a.toInt},${b.toInt},${q(e.property.toString)}]""")
          case _ => None
        }
      case _ => None
    }
  }.distinct

  // Control-dependence edges: [file, methodFullName, controllingLine, controlledLine].
  val cdg = cpg.graph.allEdges.filter(_.label == "CDG").l.flatMap { e =>
    (e.src, e.dst) match {
      case (s: CfgNode, d: CfgNode) =>
        (s.lineNumber, d.lineNumber) match {
          case (Some(a), Some(b)) if a != b =>
            val m = s.method
            if (m.isExternal) None
            else Some(s"""[${q(m.filename)},${q(m.fullName)},${a.toInt},${b.toInt}]""")
          case _ => None
        }
      case _ => None
    }
  }.distinct

  // Interprocedural taint flows from catalog sources to sink arguments
  // (regexes come from security_catalog.py via the environment).
  // Each flow: [[file, line, code], ...] with consecutive same-line steps collapsed.
  val srcRe   = sys.env.getOrElse("JOERN_SOURCE_RE", "")
  val sinkRe  = sys.env.getOrElse("JOERN_SINK_RE", "")
  val flowSec = sys.env.getOrElse("JOERN_FLOW_TIMEOUT", "120").toInt
  val flows: List[String] =
    if (srcRe.isEmpty || sinkRe.isEmpty) Nil
    else try {
      val srcs  = cpg.call.code(srcRe).l.take(400)
      val sinks = cpg.call.code(sinkRe).argument.l.take(400)
      val job   = Future { sinks.reachableByFlows(srcs).l.take(300) }
      Await.result(job, flowSec.seconds).flatMap { p =>
        val steps = p.elements.collect {
          case c: CfgNode if c.lineNumber.isDefined => (c.method.filename, c.lineNumber.get.toInt, c.code)
        }
        val collapsed = steps.foldLeft(List.empty[(String, Int, String)]) { (acc, s) =>
          acc match {
            case h :: _ if h._1 == s._1 && h._2 == s._2 => acc
            case _                                      => s :: acc
          }
        }.reverse
        if (collapsed.size < 2) None
        else Some(arr(collapsed.map { case (f, l, c) => s"""[${q(f)},$l,${q(c.take(120))}]""" }))
      }.distinct
    } catch {
      case t: Throwable =>
        System.err.println("FLOWS_SKIPPED " + t)
        Nil
    }

  val out = s"""{"methods":${arr(methodJson)},"ddg":${arr(ddg)},"cdg":${arr(cdg)},"flows":${arr(flows)}}"""
  better.files.File(outFile).write(out)
}
