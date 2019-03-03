/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef BACKENDS_BMV2_PSA_SWITCH_PSASWITCH_H_
#define BACKENDS_BMV2_PSA_SWITCH_PSASWITCH_H_

#include "ir/ir.h"
#include "lib/gmputil.h"
#include "lib/json.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include "frontends/common/constantFolding.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/coreLibrary.h"
#include "frontends/p4/enumInstance.h"
#include "frontends/p4/methodInstance.h"
#include "frontends/p4/typeMap.h"
#include "frontends/p4/simplify.h"
#include "frontends/p4/unusedDeclarations.h"
#include "backends/bmv2/common/action.h"
#include "backends/bmv2/common/control.h"
#include "backends/bmv2/common/deparser.h"
#include "backends/bmv2/common/extern.h"
#include "backends/bmv2/common/header.h"
#include "backends/bmv2/common/helpers.h"
#include "backends/bmv2/common/lower.h"
#include "backends/bmv2/common/parser.h"
#include "backends/bmv2/common/programStructure.h"

namespace BMV2 {

  class PsaProgramStructure : public ProgramStructure {
      P4::ReferenceMap*    refMap;
      P4::TypeMap*         typeMap;

   public:
      // We place scalar user metadata fields (i.e., bit<>, bool)
      // in the scalarsName metadata object, so we may need to rename
      // these fields.  This map holds the new names.
      std::vector<const IR::StructField*> scalars;
      unsigned                            scalars_width = 0;
      unsigned                            error_width = 32;
      unsigned                            bool_width = 1;

      // architecture related information
      ordered_map<const IR::Node*, std::pair<gress_t, block_t>> block_type;

      ordered_map<cstring, const IR::Type_Header*> header_types;
      ordered_map<cstring, const IR::Type_Struct*> metadata_types;
      ordered_map<cstring, const IR::Type_HeaderUnion*> header_union_types;
      ordered_map<cstring, const IR::Declaration_Variable*> headers;
      ordered_map<cstring, const IR::Declaration_Variable*> metadata;
      ordered_map<cstring, const IR::Declaration_Variable*> header_stacks;
      ordered_map<cstring, const IR::Declaration_Variable*> header_unions;
      ordered_map<cstring, const IR::Type_Error*> errors;
      ordered_map<cstring, const IR::Type_Enum*> enums;
      ordered_map<cstring, const IR::P4Parser*> parsers;
      ordered_map<cstring, const IR::P4ValueSet*> parse_vsets;
      ordered_map<cstring, const IR::P4Control*> deparsers;
      ordered_map<cstring, const IR::P4Control*> pipelines;
      ordered_map<cstring, const IR::Declaration_Instance*> extern_instances;
      ordered_map<cstring, cstring> field_aliases;

      std::vector<const IR::ExternBlock*> globals;

   public:
      PsaProgramStructure(P4::ReferenceMap* refMap, P4::TypeMap* typeMap)
          : refMap(refMap), typeMap(typeMap) {
          CHECK_NULL(refMap);
          CHECK_NULL(typeMap);
      }

      void create(ConversionContext* ctxt);
      void createStructLike(ConversionContext* ctxt, const IR::Type_StructLike* st);
      void createTypes(ConversionContext* ctxt);
      void createHeaders(ConversionContext* ctxt);
      void createParsers(ConversionContext* ctxt);
      void createExterns();
      void createActions(ConversionContext* ctxt);
      void createControls(ConversionContext* ctxt);
      void createDeparsers(ConversionContext* ctxt);
      void createGlobals();

      bool hasVisited(const IR::Type_StructLike* st) {
          if (auto h = st->to<IR::Type_Header>())
              return header_types.count(h->getName());
          else if (auto s = st->to<IR::Type_Struct>())
              return metadata_types.count(s->getName());
          else if (auto u = st->to<IR::Type_HeaderUnion>())
              return header_union_types.count(u->getName());
          return false;
      }
  };

class PsaSwitchExpressionConverter : public ExpressionConverter {
  PsaProgramStructure* structure;

 public:
    PsaSwitchExpressionConverter(P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
      PsaProgramStructure* structure, cstring scalarsName) :
      BMV2::ExpressionConverter(refMap, typeMap, structure, scalarsName), structure(structure) { }

    void modelError(const char* format, const IR::Node* node) {
        ::error(format, node);
        ::error("Are you using an up-to-date v1model.p4?");
    }

    void structuralError(const char* msg) {
        ::error(msg);
    }

    bool isStandardMetadataParameter(const IR::Parameter* param) {
        // XXX: THIS ONLY DOES THE FIRST PARSER - NEED TO GET OTHERS
        auto st = dynamic_cast<PsaProgramStructure*>(structure);

        // INGRESS PARSER
        auto ingress_parser = st->parsers.find("ingress");
        if (ingress_parser == st->parsers.end()) // should never reach this
          structuralError("PSA structural error: ingress parser not found");
        std::cout << "->>> checking " << ingress_parser->first << " pipeline now\n";

        auto params = ingress_parser->second->getApplyParameters();
        if (params->size() != 6) {
            modelError("%1%: Expected 6 parameters for parser", ingress_parser->second);
            return false;
        }
        if (params->parameters.at(3) == param) { // this check is 0-indexed
          std::cout << "->>> FOUND STD METADATA PARAM!\n";
          return true;
        }

        // EGRESS PARSER
        auto egress_parser = st->parsers.find("egress");
        if (egress_parser == st->parsers.end()) // should never reach this
          structuralError("PSA structural error: egress parser not found");
        std::cout << "->>> checking " << egress_parser->first << " pipeline now\n";

        params = egress_parser->second->getApplyParameters();
        if (params->size() != 7) {
            modelError("%1%: Expected 7 parameters for parser", egress_parser->second);
            return false;
        }
        if (params->parameters.at(3) == param) { // this check is 0-indexed
          std::cout << "->>> FOUND STD METADATA PARAM!\n";
          return true;
        }

        // INGRESS
        auto ingress = st->pipelines.find("ingress");
        if (ingress == st->pipelines.end())
          structuralError("PSA structural error: ingress control not found");
        std::cout << "->>> checking " << ingress->first << " control now\n";

        // EGRESS
        auto egress = st->pipelines.find("egress");
        if (egress == st->pipelines.end())
          structuralError("PSA structural error: ingress control not found");
        std::cout << "->>> checking " << egress->first << " control now\n";

        return false;
    }

    Util::IJson* convertParam(const IR::Parameter* param, cstring fieldName) override {
        std::cout << "starting checking now " << fieldName << "\n";
        if (isStandardMetadataParameter(param)) {
            auto result = new Util::JsonObject();
            result->emplace("type", "field");
            auto e = BMV2::mkArrayField(result, "value");
            e->append("psa_metadata");
            e->append(fieldName);
            return result;
        }
        std::cout << "made it out of stdmetadata check\n";
        LOG3("convert " << fieldName);
        return nullptr;
    }
};

class ParsePsaArchitecture : public Inspector {
    PsaProgramStructure* structure;
 public:
    explicit ParsePsaArchitecture(PsaProgramStructure* structure) :
        structure(structure) { CHECK_NULL(structure); }

    bool preorder(const IR::ToplevelBlock* block) override;
    bool preorder(const IR::PackageBlock* block) override;
    bool preorder(const IR::ExternBlock* block) override;

    profile_t init_apply(const IR::Node *root) override {
        structure->block_type.clear();
        structure->globals.clear();
        return Inspector::init_apply(root);
    }
};

class InspectPsaProgram : public Inspector {
    P4::ReferenceMap* refMap;
    P4::TypeMap* typeMap;
    PsaProgramStructure *pinfo;

 public:
    InspectPsaProgram(P4::ReferenceMap* refMap, P4::TypeMap* typeMap, PsaProgramStructure *pinfo)
        : refMap(refMap), typeMap(typeMap), pinfo(pinfo) {
        CHECK_NULL(refMap);
        CHECK_NULL(typeMap);
        CHECK_NULL(pinfo);
        setName("InspectPsaProgram");
    }

    void postorder(const IR::P4Parser *p) override;
    void postorder(const IR::P4Control* c) override;
    void postorder(const IR::Declaration_Instance* di) override;

    bool isHeaders(const IR::Type_StructLike* st);
    void addTypesAndInstances(const IR::Type_StructLike* type, bool meta);
    void addHeaderType(const IR::Type_StructLike *st);
    void addHeaderInstance(const IR::Type_StructLike *st, cstring name);
    bool preorder(const IR::Parameter* parameter) override;
};

class ConvertPsaToJson : public Inspector {
 public:
    P4::ReferenceMap *refMap;
    P4::TypeMap *typeMap;
    const IR::ToplevelBlock *toplevel;
    JsonObjects *json;
    PsaProgramStructure *structure;

    ConvertPsaToJson(P4::ReferenceMap *refMap, P4::TypeMap *typeMap,
                     const IR::ToplevelBlock *toplevel,
                     JsonObjects *json, PsaProgramStructure *structure)
        : refMap(refMap), typeMap(typeMap), toplevel(toplevel), json(json),
          structure(structure) {
        CHECK_NULL(refMap);
        CHECK_NULL(typeMap);
        CHECK_NULL(toplevel);
        CHECK_NULL(json);
        CHECK_NULL(structure); }

    void postorder(UNUSED const IR::P4Program* program) override {
        cstring scalarsName = refMap->newName("scalars");
        // This visitor is used in multiple passes to convert expression to json
        auto conv = new PsaSwitchExpressionConverter(refMap, typeMap, structure, scalarsName);
        auto ctxt = new ConversionContext(refMap, typeMap, toplevel, structure, conv, json);
        structure->create(ctxt);
    }
};

class PsaSwitchBackend : public Backend {
    BMV2Options &options;

 public:
    void convert(const IR::ToplevelBlock* tlb) override;
    PsaSwitchBackend(BMV2Options& options, P4::ReferenceMap* refMap, P4::TypeMap* typeMap,
                          P4::ConvertEnums::EnumMapping* enumMap) :
        Backend(options, refMap, typeMap, enumMap), options(options) { }
};

EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Hash)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Checksum)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(InternetChecksum)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Counter)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(DirectCounter)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Meter)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(DirectMeter)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Register)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Random)
EXTERN_CONVERTER_W_INSTANCE(ActionProfile)
EXTERN_CONVERTER_W_INSTANCE(ActionSelector)
EXTERN_CONVERTER_W_OBJECT_AND_INSTANCE(Digest)

}  // namespace BMV2

#endif  /* BACKENDS_BMV2_PSA_SWITCH_PSASWITCH_H_ */
