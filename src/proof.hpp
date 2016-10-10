#ifndef _proof_h_INCLUDED
#define _proof_h_INCLUDED

namespace CaDiCaL {

struct File;
struct Clause;
class Solver;

class Proof {
  Solver * solver;
  File * file;
  bool enabled;
  bool binary;

  void put_binary_zero ();
  void put_binary_lit (int lit);

  void trace_clause (Clause *, bool add);

public:
  Proof (Solver * s, File * f, bool b)
    : solver (s), file (f), enabled (true), binary (b)
  { }
  operator bool () const { return enabled; }
  void trace_empty_clause ();
  void trace_unit_clause (int unit);
  void trace_add_clause (Clause *);
  void trace_delete_clause (Clause *);
  void trace_flushing_clause (Clause *);
};

};

#endif