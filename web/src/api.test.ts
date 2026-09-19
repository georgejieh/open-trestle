import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY,
  hasCurrentIntegrationPermissionAuthority,
  fetchRun,
  fetchRuntimeStatus,
  fetchSetupSession,
  initializeSetup,
  parseDiagnosticEnvelope,
  parseRunEnvelope,
  parseSetupCheckResult,
  parseSetupSession,
  runSetupCheck,
  parseRuntimeStatusEnvelope,
} from "./api";
import { setupTestPlan } from "./setup-test-data";

describe("current integration diagnostic parity", () => {
  it("pins the native marker and preserves current and historical plan parsing", () => {
    expect(CURRENT_INTEGRATION_PERMISSION_CHECKER_IDENTITY).toBe(
      "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9",
    );
    // Root-native capture: pf1-setup-browser-fixture-validation.json.
    // Current: NewCurrentPlan; passed: real core IntegrationPermissionChecker/Runner
    // with a trusted core probe, NOT native broker/issuer evidence. Historical
    // records retain exact frozen pre-change bytes, labels, and timestamps.
    // SHA256 0fb784f7751223b3dd06248e5bcf424d73949e253ec92b6acb8bc556ed6e0e7f
    const currentPendingWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","previous_identity":"","checker_catalog_identity":"b0b02c3a3259a984bd22e26527531e1194bc892ba3c30967135741c53e0e9037","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":1,"tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[],"status":"incomplete","ready":false,"created_at":"2026-09-03T12:00:00Z","updated_at":"2026-09-03T12:00:00Z"}`;
    // SHA256 9f8ae573208af5f124d0a6b52305e1b8e24277b1a73cbc5bde8296849aabc145
    const currentPermissionPassedWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"afe02566f69710d5d7f7e7f55898d41be1001bbc9641cae81ce3b11a5a506d07","previous_identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","checker_catalog_identity":"b0b02c3a3259a984bd22e26527531e1194bc892ba3c30967135741c53e0e9037","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":2,"tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9","evidence_identity":"331e21772e9df49314d6b49093a67bdae04b091bbc9f49a18ecda64edaaddbdb","receipt_identity":"9faa2e5da98281f1460bde688dcfc881c18f69f65584cfe5e64811da5ebf8013","recovery_action":"","checked_at":"2026-09-03T12:00:01Z"},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"9faa2e5da98281f1460bde688dcfc881c18f69f65584cfe5e64811da5ebf8013","plan_identity":"13a7d1b6e3c8b103b33474b60abdc8c8ab4af95a75e578da58c4f98295222382","key":"integration_permissions_validated","checker_identity":"8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9","state":"passed","evidence_identity":"331e21772e9df49314d6b49093a67bdae04b091bbc9f49a18ecda64edaaddbdb","recovery_action":"","checked_at":"2026-09-03T12:00:01Z"}],"status":"incomplete","ready":false,"created_at":"2026-09-03T12:00:00Z","updated_at":"2026-09-03T12:00:01Z"}`;
    // SHA256 f51df1f3eab934c87bf0bd52274d5c5cbb1813bee7d1ae2b2e82262b37b477e4
    const historicalReadyWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"477610992d01ff93ac5142d73969b135964efa02753db4ed203bdcdd9c852f37","previous_identity":"a75d020f83f3737c28bf47432183a5559a5498801f09dcf7e5f1886087a0559a","checker_catalog_identity":"3a88cb6db2d7a6b3b9eae8aa36e4ca2a0914e6ad5138bb9e5249607d12c49b1f","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":12,"tenant_id":"pf1-tenant","repository_id":"pf1-repository","recovery_owner":"pf1-owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"passed","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0","evidence_identity":"afdf43c9ce57573fb0831000ea91485b5788817460f415964cc862f144bcdbcd","receipt_identity":"e6ccc9cd6d623b492f70d8172bd57a34ca3b6541c5c57bb25276daaa3f8837d4","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"key":"envelope_storage_validated","source":"probe","state":"passed","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb","evidence_identity":"97a973f85cb76a13eca66a95185da744ffa6da2e5bd2f3c4e0f8613d9e8bd1d8","receipt_identity":"bd17419c5716aeb1b5414cc8ec426491b278af538c6e6b43421ce0511b7b2cda","recovery_action":"","checked_at":"2026-09-06T12:00:01.001Z"},{"key":"backup_validated","source":"probe","state":"passed","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679","evidence_identity":"60d78552e0d35c7dc13dd9cfd89e1ff76b76323f4829ab7e717277a7936082a5","receipt_identity":"f70d4f88408098e5aed8dcd3d508c89de0f659ef405f771bd9b25319d17d2d14","recovery_action":"","checked_at":"2026-09-06T12:00:01.002Z"},{"key":"secret_backend_validated","source":"probe","state":"passed","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df","evidence_identity":"82c9265bbda4030565eea12350c71c5604409cca19d50b24895de8da4a3346f2","receipt_identity":"168d52f394f9802792fe0cac82f61f085dbb279558b5793dacf36f90baa40f9a","recovery_action":"","checked_at":"2026-09-06T12:00:01.003Z"},{"key":"local_administrator_validated","source":"authorization","state":"passed","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89","evidence_identity":"0e09d600dc0b958727c51537c3d760e15fdd8f73322be300b5118342d565c9d9","receipt_identity":"080724ca251b744f12169dc9bb19445b2fa09798d9b6cb472e1b4ab69ff06fc2","recovery_action":"","checked_at":"2026-09-06T12:00:01.004Z"},{"key":"observer_credential_posture_validated","source":"probe","state":"passed","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542","evidence_identity":"1bb95ae746cd621e886b1831c792e05977fd3dcc44c94ffb3ae44a66ca5c90af","receipt_identity":"31fe3119d38c1b0386480009334984ff588ef17cecc33ae6972c2c906b02bd01","recovery_action":"","checked_at":"2026-09-06T12:00:01.005Z"},{"key":"remote_provider_authorized","source":"authorization","state":"passed","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1","evidence_identity":"01db8e6c239d45b64dcc49dba8021a2f5ab7bcb5da37ce302743f3e65089b824","receipt_identity":"982fefeb83039ceaf3c64434d58a4dc443e6fa700c564590c38c14b85267a7cf","recovery_action":"","checked_at":"2026-09-06T12:00:01.006Z"},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","receipt_identity":"81ec1517b94e0a5df85a56251fe1048c243039b6e963ebd5a5b0a9358f5b35f3","recovery_action":"","checked_at":"2026-09-06T12:00:01.007Z"},{"key":"webhook_validated","source":"probe","state":"passed","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e","evidence_identity":"c80e12afbac08c60399042e84dd2fc53f95f4ca8e70eb24ff25cf4c3b3f01302","receipt_identity":"8d8c425303a6c5159eafa9588e648dbaf832bffedf0e6118c95e85f86725007e","recovery_action":"","checked_at":"2026-09-06T12:00:01.008Z"},{"key":"policy_validated","source":"authorization","state":"passed","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4","evidence_identity":"53583fabf316124a6e15f929f1cfc2abd5614b35fd87b6b267dd217e477a0b64","receipt_identity":"4a884c2c4069219a5d4d6a108510c60e82402ab527f9e456cce87f6955eeea48","recovery_action":"","checked_at":"2026-09-06T12:00:01.009Z"},{"key":"dry_run_validated","source":"dry_run","state":"passed","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df","evidence_identity":"50a76f53896eb3cb0eed810e012cab4891dee773c6c63a31c50af6e68c61dbd0","receipt_identity":"ac91aee87a2546952f98a430df39f9b223b262b807fd2aad811e338e270dd9f0","recovery_action":"","checked_at":"2026-09-06T12:00:01.01Z"}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"e6ccc9cd6d623b492f70d8172bd57a34ca3b6541c5c57bb25276daaa3f8837d4","plan_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0","state":"passed","evidence_identity":"afdf43c9ce57573fb0831000ea91485b5788817460f415964cc862f144bcdbcd","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"bd17419c5716aeb1b5414cc8ec426491b278af538c6e6b43421ce0511b7b2cda","plan_identity":"d481bdd10feda83553c2e2399fa5d826b44b01ac5a8506bbb6daa63138390254","key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb","state":"passed","evidence_identity":"97a973f85cb76a13eca66a95185da744ffa6da2e5bd2f3c4e0f8613d9e8bd1d8","recovery_action":"","checked_at":"2026-09-06T12:00:01.001Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"f70d4f88408098e5aed8dcd3d508c89de0f659ef405f771bd9b25319d17d2d14","plan_identity":"2769d3661c6c5081c0992409965769b137100d76b830c6b429107502f8ccd492","key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679","state":"passed","evidence_identity":"60d78552e0d35c7dc13dd9cfd89e1ff76b76323f4829ab7e717277a7936082a5","recovery_action":"","checked_at":"2026-09-06T12:00:01.002Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"168d52f394f9802792fe0cac82f61f085dbb279558b5793dacf36f90baa40f9a","plan_identity":"47b2a88dff5967bc151e88300c1bfa80a5f5b998d5bbb80c6f93f56f7d524122","key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df","state":"passed","evidence_identity":"82c9265bbda4030565eea12350c71c5604409cca19d50b24895de8da4a3346f2","recovery_action":"","checked_at":"2026-09-06T12:00:01.003Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"080724ca251b744f12169dc9bb19445b2fa09798d9b6cb472e1b4ab69ff06fc2","plan_identity":"75b2d790e3e3b38a3e55b9cade48a58833571ab4279670b9f94d477127687317","key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89","state":"passed","evidence_identity":"0e09d600dc0b958727c51537c3d760e15fdd8f73322be300b5118342d565c9d9","recovery_action":"","checked_at":"2026-09-06T12:00:01.004Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"31fe3119d38c1b0386480009334984ff588ef17cecc33ae6972c2c906b02bd01","plan_identity":"d6e0e5c9414dd479fd15befc8805bb75530bbafe8729d8e1ccbc852a1d489c73","key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542","state":"passed","evidence_identity":"1bb95ae746cd621e886b1831c792e05977fd3dcc44c94ffb3ae44a66ca5c90af","recovery_action":"","checked_at":"2026-09-06T12:00:01.005Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"982fefeb83039ceaf3c64434d58a4dc443e6fa700c564590c38c14b85267a7cf","plan_identity":"aa4f045f2a6e955c2ce6930b3251408db81659e9758f6930a6b4eaef1bc08d7a","key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1","state":"passed","evidence_identity":"01db8e6c239d45b64dcc49dba8021a2f5ab7bcb5da37ce302743f3e65089b824","recovery_action":"","checked_at":"2026-09-06T12:00:01.006Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"81ec1517b94e0a5df85a56251fe1048c243039b6e963ebd5a5b0a9358f5b35f3","plan_identity":"4395e7b90fea4124a8256ca3c2ed599d447fa264807a848944172c4d6e7d8aab","key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","state":"passed","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","recovery_action":"","checked_at":"2026-09-06T12:00:01.007Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"8d8c425303a6c5159eafa9588e648dbaf832bffedf0e6118c95e85f86725007e","plan_identity":"96204a0eb0c85fe62f99d37e3d268b7869a7eff34ce1995aa9c1c368f7afd49a","key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e","state":"passed","evidence_identity":"c80e12afbac08c60399042e84dd2fc53f95f4ca8e70eb24ff25cf4c3b3f01302","recovery_action":"","checked_at":"2026-09-06T12:00:01.008Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"4a884c2c4069219a5d4d6a108510c60e82402ab527f9e456cce87f6955eeea48","plan_identity":"a175e88e2983cddf6f38381c21f80a2793d711b143d55449e74941163eb2a2fc","key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4","state":"passed","evidence_identity":"53583fabf316124a6e15f929f1cfc2abd5614b35fd87b6b267dd217e477a0b64","recovery_action":"","checked_at":"2026-09-06T12:00:01.009Z"},{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"ac91aee87a2546952f98a430df39f9b223b262b807fd2aad811e338e270dd9f0","plan_identity":"a75d020f83f3737c28bf47432183a5559a5498801f09dcf7e5f1886087a0559a","key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df","state":"passed","evidence_identity":"50a76f53896eb3cb0eed810e012cab4891dee773c6c63a31c50af6e68c61dbd0","recovery_action":"","checked_at":"2026-09-06T12:00:01.01Z"}],"status":"ready","ready":true,"created_at":"2026-09-06T12:00:00Z","updated_at":"2026-09-06T12:00:01.01Z"}`;
    // SHA256 58425526d29840ff1835a8c59797f3495b43dd58f8eaf6819ba2c219c24d8c06
    const historicalPendingWire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","previous_identity":"","checker_catalog_identity":"3a88cb6db2d7a6b3b9eae8aa36e4ca2a0914e6ad5138bb9e5249607d12c49b1f","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":1,"tenant_id":"pf1-tenant","repository_id":"pf1-repository","recovery_owner":"pf1-owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[],"status":"incomplete","ready":false,"created_at":"2026-09-06T12:00:00Z","updated_at":"2026-09-06T12:00:00Z"}`;
    for (const [wire, current] of [
      [currentPendingWire, true],
      [currentPermissionPassedWire, true],
      [historicalReadyWire, false],
      [historicalPendingWire, false],
    ] as const) {
      const plan = parseSetupSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: true,
        plan: JSON.parse(wire),
      }).plan!;
      expect(hasCurrentIntegrationPermissionAuthority(plan)).toBe(current);
      expect(JSON.stringify(plan)).toBe(wire);
    }
    expect(hasCurrentIntegrationPermissionAuthority(setupTestPlan())).toBe(
      false,
    );
  });
});

const digest = "a".repeat(64);
const run = {
  contract: "open-trestle/review-run-receipt",
  schema_version: 1,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  review_run_id: "run-a",
  status: "active",
  revision: 1,
  head_identity: digest,
  last_occurred_at_milliseconds: 1000,
  output_identity: "",
  failure: "",
  tasks: [
    {
      key: "source",
      task_identity: digest,
      input_identity: digest,
      handler_identity: digest,
      kind: "acquire_source",
      required: true,
      status: "available",
      attempts: 0,
      max_attempts: 1,
      lease_expires_at_milliseconds: 0,
      output_identity: "",
      failure: "",
      retry_at_milliseconds: 0,
    },
  ],
};

const runtimeStatus = {
  contract: "open-trestle/runtime-status",
  schema_version: 1,
  identity: "b".repeat(64),
  configuration_identity: "c".repeat(64),
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  observed_at: "2026-09-03T12:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["repo-a"],
    metadata_backend: "local",
    artifact_backend: "local",
    artifact_protection: "process_private",
    notification_backend: "process_local",
    rate_limit_backend: "process_local",
    review_mode: "disabled",
    webhook_ingress: false,
    local_workers: false,
    publication_enabled: false,
    publication_fence_verified: false,
    route_count: 0,
    handlers: [],
  },
  components: [{ name: "task_notifications", state: "ready" }],
};

describe("API client", () => {
  it("accepts an exact scoped run envelope", () => {
    expect(
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run,
      }),
    ).toEqual(run);
  });
  it("rejects unknown and cross-scoped response fields", () => {
    expect(() =>
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run: { ...run, extra: true },
      }),
    ).toThrow(ApiError);
    expect(() =>
      parseRunEnvelope(
        {
          contract: "open-trestle/api-response",
          schema_version: 1,
          request_id: "request-a",
          run: { ...run, tenant_id: "tenant-b" },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });
  it("rejects duplicate durable task identities", () => {
    expect(() =>
      parseRunEnvelope({
        contract: "open-trestle/api-response",
        schema_version: 1,
        request_id: "request-a",
        run: { ...run, tasks: [run.tasks[0], run.tasks[0]] },
      }),
    ).toThrow(ApiError);
  });
  it("parses diagnostic v2 coverage and rejects impossible accounting", () => {
    const diagnostic = {
      identity: "b".repeat(64),
      source_identity: "c".repeat(64),
      fingerprint: "d".repeat(64),
      title: "Verified issue",
      message: "The independently verified issue remains.",
      severity: "warning",
      path: "internal/example.go",
      start_line: 4,
      end_line: 4,
      evidence_ids: ["evidence"],
    };
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 2,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 3,
        verified_count: 1,
        rejected_count: 1,
        inconclusive_count: 1,
      },
      findings: [diagnostic],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      parseDiagnosticEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
        run: "run-a",
      }).coverage,
    ).toEqual(diagnostics.coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            coverage: { ...diagnostics.coverage, rejected_count: 2 },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v3 source coverage and rejects impossible accounting", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 3,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 1,
        verified_count: 0,
        rejected_count: 1,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 173,
        selected_count: 1,
        omitted_count: 172,
      },
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      parseDiagnosticEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
        run: "run-a",
      }).source_coverage,
    ).toEqual(diagnostics.source_coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              ...diagnostics.source_coverage,
              omitted_count: 171,
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: { ...diagnostics, schema_version: 2 },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              verification_context_identity: "4".repeat(64),
              analyzed_count: 0,
              selected_count: 0,
              omitted_count: 0,
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v4 omission reasons and rejects noncanonical summaries", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 4,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 0,
        verified_count: 0,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 3,
        selected_count: 1,
        omitted_count: 2,
        omissions: [
          { reason: "authorization", count: 1 },
          { reason: "selection_limit", count: 1 },
        ],
      },
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    expect(
      parseDiagnosticEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
        run: "run-a",
      }).source_coverage,
    ).toEqual(diagnostics.source_coverage);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            source_coverage: {
              ...diagnostics.source_coverage,
              omissions: [...diagnostics.source_coverage.omissions].reverse(),
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("parses diagnostic v5 deterministic checks and rejects impossible state", () => {
    const diagnostics = {
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 5,
      identity: "f".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      coverage: {
        candidate_count: 0,
        verified_count: 0,
        rejected_count: 0,
        inconclusive_count: 0,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 1,
        selected_count: 1,
        omitted_count: 0,
        omissions: [],
      },
      checks: [
        {
          identity: "5".repeat(64),
          source_check_identity: "6".repeat(64),
          analysis_result_identity: "7".repeat(64),
          change_identity: "8".repeat(64),
          key: "static_debug_output",
          rule_version: 1,
          state: "passed",
          applicable_files: 1,
          applicable_ranges: 2,
          checked_files: 1,
          checked_ranges: 2,
          matches: 0,
        },
      ],
      findings: [],
    };
    const envelope = {
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      diagnostics,
    };
    const parsed = parseDiagnosticEnvelope(envelope, {
      tenant: "tenant-a",
      repository: "repo-a",
      run: "run-a",
    });
    expect(parsed.schema_version).toBe(5);
    if (parsed.schema_version !== 5) throw new Error("expected v5");
    expect(parsed.checks).toEqual(diagnostics.checks);
    expect(() =>
      parseDiagnosticEnvelope(
        {
          ...envelope,
          diagnostics: {
            ...diagnostics,
            checks: [{ ...diagnostics.checks[0], matches: 1 }],
          },
        },
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      ),
    ).toThrow(ApiError);
  });

  it("requires dependent setup checks to reset after prerequisite replacement", () => {
    const plan = setupTestPlan();
    const identity = (value: number) => value.toString(16).padStart(64, "0");
    const sequence = [
      "policy_validated",
      "local_inference_validated",
      "dry_run_validated",
      "policy_validated",
    ] as const;
    for (const [index, key] of sequence.entries()) {
      const checker = plan.checker_authorities.find(
        (entry) => entry.key === key,
      )!;
      const receipt = {
        contract: "open-trestle/setup-check-receipt" as const,
        schema_version: 1 as const,
        identity: identity(100 + index),
        plan_identity: index === 0 ? plan.identity : identity(200 + index),
        key,
        checker_identity: checker.checker_identity,
        state: "passed" as const,
        evidence_identity: identity(300 + index),
        recovery_action: "",
        checked_at: new Date(
          Date.parse(plan.created_at) + index + 1,
        ).toISOString(),
      };
      plan.receipts.push(receipt);
      plan.requirements = plan.requirements.map((requirement) =>
        requirement.key !== key
          ? requirement
          : {
              ...requirement,
              state: receipt.state,
              checker_identity: receipt.checker_identity,
              evidence_identity: receipt.evidence_identity,
              receipt_identity: receipt.identity,
              recovery_action: "",
              checked_at: receipt.checked_at,
            },
      );
    }
    plan.revision = plan.receipts.length + 1;
    plan.identity = identity(400);
    plan.previous_identity = plan.receipts.at(-1)!.plan_identity;
    plan.updated_at = plan.receipts.at(-1)!.checked_at;
    const stale = structuredClone(plan);
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "local_inference_validated" ||
      requirement.key === "dry_run_validated"
        ? {
            ...requirement,
            state: "pending",
            checker_identity: "",
            evidence_identity: "",
            receipt_identity: "",
            recovery_action: "",
            checked_at: "",
          }
        : requirement,
    );
    const envelope = {
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    };
    expect(parseSetupSession(envelope).plan).toEqual(plan);
    expect(() => parseSetupSession({ ...envelope, plan: stale })).toThrow(
      ApiError,
    );
  });

  it("uses a bounded, no-store, no-redirect authenticated request", async () => {
    const fetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "request-a",
            run,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await fetchRun(
      { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      "x".repeat(32),
      fetcher,
    );
    const [url, init] = fetcher.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a");
    expect(init.redirect).toBe("error");
    expect(init.cache).toBe("no-store");
    expect((init.headers as Headers).get("Authorization")).toBe(
      `Bearer ${"x".repeat(32)}`,
    );
  });

  it("allows bounded API framing beyond a one MiB payload", async () => {
    const envelope = JSON.stringify({
      contract: "open-trestle/api-response",
      schema_version: 1,
      request_id: "request-a",
      run,
    });
    const framed = " ".repeat((1 << 20) + 128 - envelope.length) + envelope;
    const fetcher = vi.fn(
      async () =>
        new Response(framed, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    const received = await fetchRun(
      { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
      "x".repeat(32),
      fetcher,
    );
    expect(received).toEqual(run);
  });

  it("stops an unframed response once the byte limit is exceeded", async () => {
    const chunk = new Uint8Array(600_000);
    const fetcher = vi.fn(
      async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(chunk);
              controller.enqueue(chunk);
              controller.close();
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        fetcher,
      ),
    ).rejects.toThrow(ApiError);
  });
  it("accepts exact scoped runtime status and rejects cross-scope metadata", () => {
    const envelope = {
      contract: "open-trestle/runtime-status-response",
      schema_version: 1,
      request_id: "request-a",
      status: runtimeStatus,
    };
    expect(
      parseRuntimeStatusEnvelope(envelope, {
        tenant: "tenant-a",
        repository: "repo-a",
      }),
    ).toEqual(runtimeStatus);
    expect(() =>
      parseRuntimeStatusEnvelope(
        {
          ...envelope,
          status: {
            ...runtimeStatus,
            configuration: {
              ...runtimeStatus.configuration,
              repository_ids: ["repo-a", "repo-b"],
            },
          },
        },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).toThrow(ApiError);
    expect(() =>
      parseRuntimeStatusEnvelope(
        { ...envelope, status: { ...runtimeStatus, ready: false } },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).toThrow(ApiError);
  });
  it("rejects impossible runtime state and normalized calendar dates", () => {
    const envelope = (status: unknown) => ({
      contract: "open-trestle/runtime-status-response",
      schema_version: 1,
      request_id: "request-a",
      status,
    });
    const configurations = [
      {
        ...runtimeStatus.configuration,
        handlers: [{ kind: "acquire_source", identity: "d".repeat(64) }],
      },
      {
        ...runtimeStatus.configuration,
        review_mode: "advisory",
        local_workers: true,
      },
      {
        ...runtimeStatus.configuration,
        review_mode: "advisory",
        handlers: [
          { kind: "acquire_source", identity: "d".repeat(64) },
          { kind: "acquire_source", identity: "e".repeat(64) },
        ],
      },
    ];
    for (const configuration of configurations)
      expect(() =>
        parseRuntimeStatusEnvelope(
          envelope({ ...runtimeStatus, configuration }),
          { tenant: "tenant-a", repository: "repo-a" },
        ),
      ).toThrow(ApiError);
    expect(() =>
      parseRuntimeStatusEnvelope(
        envelope({ ...runtimeStatus, observed_at: "2026-02-30T12:00:00Z" }),
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).toThrow(ApiError);
  });

  it("fetches runtime status through the repository endpoint", async () => {
    const fetcher = vi.fn(
      async (_input: string, _init: RequestInit) =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/runtime-status-response",
            schema_version: 1,
            request_id: "request-a",
            status: runtimeStatus,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await fetchRuntimeStatus(
      { tenant: "tenant-a", repository: "repo-a" },
      "x".repeat(32),
      fetcher,
    );
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      "/api/v1/tenants/tenant-a/repositories/repo-a/runtime",
    );
  });

  it("parses exact setup sessions and rejects false readiness", () => {
    const plan = setupTestPlan();
    expect(
      parseSetupSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: true,
        plan,
      }),
    ).toEqual({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    expect(
      parseSetupSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: false,
      }),
    ).toEqual({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: false,
    });
    expect(() =>
      parseSetupSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: true,
        plan: { ...plan, status: "ready", ready: true },
      }),
    ).toThrow(ApiError);
    expect(() =>
      parseSetupSession({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: false,
        plan,
      }),
    ).toThrow(ApiError);
  });
  it("binds a setup check result to the newest plan receipt", () => {
    const plan = setupTestPlan(true),
      receipt = plan.receipts[0]!;
    expect(
      parseSetupCheckResult({
        contract: "open-trestle/setup-check-result",
        schema_version: 1,
        plan,
        receipt,
      }),
    ).toEqual({
      contract: "open-trestle/setup-check-result",
      schema_version: 1,
      plan,
      receipt,
    });
    expect(() =>
      parseSetupCheckResult({
        contract: "open-trestle/setup-check-result",
        schema_version: 1,
        plan,
        receipt: { ...receipt, plan_identity: "f".repeat(64) },
      }),
    ).toThrow(ApiError);
  });
  it("uses bounded credential-free setup request bodies", async () => {
    const plan = setupTestPlan(),
      next = setupTestPlan(true),
      receipt = next.receipts[0]!;
    const fetcher = vi.fn(
      async (input: string, _init: RequestInit) =>
        new Response(
          JSON.stringify(
            input.endsWith("/init")
              ? {
                  contract: "open-trestle/setup-session",
                  schema_version: 1,
                  initialized: true,
                  plan,
                }
              : input.endsWith("/check")
                ? {
                    contract: "open-trestle/setup-check-result",
                    schema_version: 1,
                    plan: next,
                    receipt,
                  }
                : {
                    contract: "open-trestle/setup-session",
                    schema_version: 1,
                    initialized: false,
                  },
          ),
          {
            status: input.endsWith("/init") ? 201 : 200,
            headers: { "content-type": "application/json" },
          },
        ),
    );
    const token = "s".repeat(32);
    await fetchSetupSession(token, fetcher);
    await initializeSetup(
      {
        profile: "local_single_node",
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        recovery_owner: "owner",
      },
      token,
      fetcher,
    );
    await runSetupCheck(
      {
        plan_identity: plan.identity,
        key: "observer_credential_posture_validated",
      },
      token,
      fetcher,
    );
    const init = fetcher.mock.calls[1]![1] as RequestInit,
      check = fetcher.mock.calls[2]![1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      contract: "open-trestle/setup-init-request",
      schema_version: 1,
      profile: "local_single_node",
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      recovery_owner: "owner",
      confirmation: "create setup plan",
    });
    expect(JSON.parse(check.body as string)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: plan.identity,
      key: "observer_credential_posture_validated",
      confirmation: "run observer_credential_posture_validated",
    });
    expect((check.headers as Headers).get("Authorization")).toBe(
      `Bearer ${token}`,
    );
    expect(check.credentials).toBe("omit");
  });

  it("rejects unknown setup error codes", () => {
    expect(() =>
      parseSetupCheckResult({
        contract: "open-trestle/setup-error",
        schema_version: 1,
        code: "provider_body",
      }),
    ).toThrow(ApiError);
    expect(() =>
      parseSetupSession({
        contract: "open-trestle/setup-error",
        schema_version: 1,
        code: "unauthorized",
      }),
    ).toThrow(ApiError);
  });

  it("rejects crossed setup mutation responses and status mismatches", async () => {
    const plan = setupTestPlan(),
      crossed = { ...plan, tenant_id: "tenant-b" };
    const token = "s".repeat(32);
    const initFetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-session",
            schema_version: 1,
            initialized: true,
            plan: crossed,
          }),
          { status: 201, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(
      initializeSetup(
        {
          profile: "local_single_node",
          tenant_id: "tenant-a",
          repository_id: "repo-a",
          recovery_owner: "owner",
        },
        token,
        initFetcher,
      ),
    ).rejects.toThrow(ApiError);
    const statusFetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-session",
            schema_version: 1,
            initialized: true,
            plan,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(
      initializeSetup(
        {
          profile: "local_single_node",
          tenant_id: "tenant-a",
          repository_id: "repo-a",
          recovery_owner: "owner",
        },
        token,
        statusFetcher,
      ),
    ).rejects.toThrow(ApiError);
    const next = setupTestPlan(true),
      receipt = next.receipts[0]!;
    const checkFetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-check-result",
            schema_version: 1,
            plan: next,
            receipt,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(
      runSetupCheck(
        {
          plan_identity: plan.identity,
          key: "state_storage_posture_validated",
          storage_root: "/safe",
        },
        token,
        checkFetcher,
      ),
    ).rejects.toThrow(ApiError);
  });
  it("rejects duplicate response keys and malformed JSON media types", async () => {
    const duplicate = `{"contract":"open-trestle/api-response","contract":"open-trestle/api-response","schema_version":1,"request_id":"request-a","run":${JSON.stringify(run)}}`;
    const duplicateFetcher = vi.fn(
      async () =>
        new Response(duplicate, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        duplicateFetcher,
      ),
    ).rejects.toThrow(ApiError);
    const mediaFetcher = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/api-response",
            schema_version: 1,
            request_id: "request-a",
            run,
          }),
          {
            status: 200,
            headers: { "content-type": "application/json-whatever" },
          },
        ),
    );
    await expect(
      fetchRun(
        { tenant: "tenant-a", repository: "repo-a", run: "run-a" },
        "x".repeat(32),
        mediaFetcher,
      ),
    ).rejects.toThrow(ApiError);
  });

  it("requires setup error codes to match HTTP status", async () => {
    const token = "s".repeat(32);
    const accepted = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-error",
            schema_version: 1,
            code: "unauthorized",
          }),
          { status: 401, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(fetchSetupSession(token, accepted)).rejects.toMatchObject({
      code: "unauthorized",
    });
    const crossed = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-error",
            schema_version: 1,
            code: "unauthorized",
          }),
          { status: 409, headers: { "content-type": "application/json" } },
        ),
    );
    await expect(fetchSetupSession(token, crossed)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("rejects escaped and nested duplicate response members", async () => {
    const escaped = String.raw`{"contract":"open-trestle/setup-session","schema_version":1,"initialized":false,"\u0069nitialized":false}`;
    const fetcher = vi.fn(
      async () =>
        new Response(escaped, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(
      fetchSetupSession("s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "invalid_response" });
    const nested = `{"contract":"open-trestle/setup-session","schema_version":1,"initialized":true,"plan":{"x":1,"x":1}}`;
    const nestedFetcher = vi.fn(
      async () =>
        new Response(nested, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    await expect(
      fetchSetupSession("s".repeat(32), nestedFetcher),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("serializes only the selected offline setup check fields", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const token = "s".repeat(32),
      plan = "a".repeat(64);
    await expect(
      runSetupCheck(
        {
          plan_identity: plan,
          key: "local_administrator_validated",
          approved_by: "owner",
        },
        token,
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "check_failed" });
    await expect(
      runSetupCheck(
        {
          plan_identity: plan,
          key: "backup_validated",
          backup_snapshot_path: "/private/backup.json",
        },
        token,
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "check_failed" });

    const policyFields = {
      route_inventory_path: "/private/routes.json",
      runtime_policy_path: "/private/policy.json",
      approve_inventory_identity: "1".repeat(64),
      approve_runtime_policy_identity: "2".repeat(64),
      approve_review_policy_identity: "3".repeat(64),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(
        {
          plan_identity: plan,
          key: "local_inference_validated",
          ...policyFields,
        },
        token,
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: plan,
      key: "local_administrator_validated",
      confirmation: "run local_administrator_validated",
      approved_by: "owner",
    });
    expect(JSON.parse(calls[1]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: plan,
      key: "backup_validated",
      confirmation: "run backup_validated",
      backup_snapshot_path: "/private/backup.json",
    });
    expect(JSON.parse(calls[2]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: plan,
      key: "local_inference_validated",
      confirmation: "run local_inference_validated",
      ...policyFields,
    });
  });

  it("serializes the exact PostgreSQL setup approval", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "postgres_storage_validated" as const,
      approve_postgres_authority_identity: "b".repeat(64),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run postgres_storage_validated",
      approve_postgres_authority_identity:
        input.approve_postgres_authority_identity,
      approved_by: "owner",
    });
  });

  it("serializes the exact KMS secret-backend approval", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "secret_backend_validated" as const,
      approve_kms_authority_identity: "b".repeat(64),
      kms_region: "us-east-1",
      kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/example",
      kms_endpoint: "https://kms.example",
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run secret_backend_validated",
      approve_kms_authority_identity: input.approve_kms_authority_identity,
      kms_region: input.kms_region,
      kms_key_arn: input.kms_key_arn,
      kms_endpoint: input.kms_endpoint,
      approved_by: "owner",
    });
  });

  it("serializes the exact envelope-storage approval", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "envelope_storage_validated" as const,
      approve_envelope_storage_authority_identity: "b".repeat(64),
      s3_endpoint: "https://s3.example",
      s3_region: "us-east-1",
      s3_bucket: "artifacts",
      s3_prefix: "reviews",
      kms_region: "us-east-1",
      kms_key_arn: "arn:aws:kms:us-east-1:123456789012:key/example",
      kms_endpoint: "https://kms.example",
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run envelope_storage_validated",
      approve_envelope_storage_authority_identity:
        input.approve_envelope_storage_authority_identity,
      s3_endpoint: input.s3_endpoint,
      s3_region: input.s3_region,
      s3_bucket: input.s3_bucket,
      s3_prefix: input.s3_prefix,
      kms_region: input.kms_region,
      kms_key_arn: input.kms_key_arn,
      kms_endpoint: input.kms_endpoint,
      approved_by: "owner",
    });
  });

  it("serializes remote-provider authorization without a credential value", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "remote_provider_authorized" as const,
      route_inventory_path: "/routes",
      runtime_policy_path: "/policy",
      approve_inventory_identity: "1".repeat(64),
      approve_runtime_policy_identity: "2".repeat(64),
      approve_review_policy_identity: "3".repeat(64),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run remote_provider_authorized",
      route_inventory_path: "/routes",
      runtime_policy_path: "/policy",
      approve_inventory_identity: input.approve_inventory_identity,
      approve_runtime_policy_identity: input.approve_runtime_policy_identity,
      approve_review_policy_identity: input.approve_review_policy_identity,
      approved_by: "owner",
    });
  });

  it("serializes shared rate-limit authority without a database URL", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "shared_rate_limit_validated" as const,
      approve_shared_rate_limit_authority_identity: "b".repeat(64),
      postgres_database_authority_identity: "c".repeat(64),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run shared_rate_limit_validated",
      approve_shared_rate_limit_authority_identity:
        input.approve_shared_rate_limit_authority_identity,
      postgres_database_authority_identity:
        input.postgres_database_authority_identity,
      approved_by: "owner",
    });
    expect(calls[0]).not.toContain("postgres://");
    await expect(
      runSetupCheck(
        { ...input, postgres_database_authority_identity: "0".repeat(64) },
        "s".repeat(32),
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(calls).toHaveLength(1);
  });

  it("serializes replica reconciliation authority without a database URL", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "replica_reconciliation_validated" as const,
      approve_replica_reconciliation_authority_identity: "b".repeat(64),
      postgres_database_authority_identity: "c".repeat(64),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run replica_reconciliation_validated",
      approve_replica_reconciliation_authority_identity:
        input.approve_replica_reconciliation_authority_identity,
      postgres_database_authority_identity:
        input.postgres_database_authority_identity,
      approved_by: "owner",
    });
    expect(calls[0]).not.toContain("postgres://");
    await expect(
      runSetupCheck(
        {
          ...input,
          approve_replica_reconciliation_authority_identity: "0".repeat(64),
        },
        "s".repeat(32),
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(calls).toHaveLength(1);
  });

  it("serializes an opaque signed-bundle check without bundle content", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "signed_bundle_validated" as const,
      approve_signed_bundle_authority_identity: "b".repeat(64),
      bundle_path: "/private/release.bundle",
      bundle_sha256: "c".repeat(64),
      bundle_bytes: 1024,
      public_key: "d".repeat(64),
      signature: "e".repeat(128),
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run signed_bundle_validated",
      approve_signed_bundle_authority_identity:
        input.approve_signed_bundle_authority_identity,
      bundle_path: input.bundle_path,
      bundle_sha256: input.bundle_sha256,
      bundle_bytes: input.bundle_bytes,
      public_key: input.public_key,
      signature: input.signature,
      approved_by: "owner",
    });
    for (const bundle_path of [
      "relative.bundle",
      "/private/../release.bundle",
      "/private//release.bundle",
    ])
      await expect(
        runSetupCheck({ ...input, bundle_path }, "s".repeat(32), fetcher),
      ).rejects.toMatchObject({ code: "invalid_scope" });
    await expect(
      runSetupCheck(
        { ...input, signature: "0".repeat(128) },
        "s".repeat(32),
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(calls).toHaveLength(1);
  });

  it("serializes exact GitHub permission inspection without a token", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "stale_plan",
        }),
        { status: 409, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "integration_permissions_validated" as const,
      approve_integration_permission_authority_identity: "b".repeat(64),
      approve_github_source_broker_authority_identity: "c".repeat(64),
      allow_github_installation_token_creation: true,
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "stale_plan" });
    expect(calls[0]).toBe(
      JSON.stringify({
        contract: "open-trestle/setup-check-request",
        schema_version: 2,
        plan_identity: input.plan_identity,
        key: input.key,
        confirmation:
          "create GitHub installation token and run integration_permissions_validated",
        approve_integration_permission_authority_identity:
          input.approve_integration_permission_authority_identity,
        approve_github_source_broker_authority_identity:
          input.approve_github_source_broker_authority_identity,
        allow_github_installation_token_creation: true,
        approved_by: "owner",
      }),
    );
    expect(calls[0]).not.toContain("s".repeat(32));
    for (const invalid of [
      { allow_github_installation_token_creation: false },
      { allow_github_installation_token_creation: undefined },
      { allow_github_installation_token_creation: null },
      { allow_github_installation_token_creation: "true" },
      { approve_github_source_broker_authority_identity: "0".repeat(64) },
      { approve_github_source_broker_authority_identity: undefined },
      { approve_integration_permission_authority_identity: "B".repeat(64) },
      { approved_by: "" },
      { plan_identity: "0".repeat(64) },
      { github_api_endpoint: "https://api.github.com" },
      { github_api_endpoint: undefined },
      { configuration: {} },
      { token: "not-a-token" },
      { github_api_version: "2026-03-10" },
      { github_installation_id: 42 },
      { github_repository_full_name: "owner/repository" },
      { broker_config: "/private/config.json" },
      { private_key: "not-a-key" },
      { storage_root: "/private" },
    ])
      await expect(
        runSetupCheck(
          { ...input, ...invalid } as unknown as Parameters<
            typeof runSetupCheck
          >[0],
          "s".repeat(32),
          fetcher,
        ),
      ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(calls).toHaveLength(1);
  });

  it("retains unrelated v1 requests and refuses mixed broker consent", async () => {
    const fetcher = vi.fn(
      async (_input: string, _init: RequestInit) =>
        new Response(
          JSON.stringify({
            contract: "open-trestle/setup-error",
            schema_version: 1,
            code: "check_failed",
          }),
          { status: 422, headers: { "content-type": "application/json" } },
        ),
    );
    const input = {
      plan_identity: "a".repeat(64),
      key: "observer_credential_posture_validated" as const,
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    const init = fetcher.mock.calls[0]![1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run observer_credential_posture_validated",
    });
    for (const mixed of [
      { allow_github_installation_token_creation: false },
      { approve_github_source_broker_authority_identity: "" },
    ])
      await expect(
        runSetupCheck({ ...input, ...mixed }, "s".repeat(32), fetcher),
      ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("serializes webhook conformance authority without a secret", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn(async (_input: string, init: RequestInit) => {
      calls.push(init.body as string);
      return new Response(
        JSON.stringify({
          contract: "open-trestle/setup-error",
          schema_version: 1,
          code: "check_failed",
        }),
        { status: 422, headers: { "content-type": "application/json" } },
      );
    });
    const input = {
      plan_identity: "a".repeat(64),
      key: "webhook_validated" as const,
      approve_webhook_authority_identity: "b".repeat(64),
      github_webhook_key_id: "primary-2026",
      approved_by: "owner",
    };
    await expect(
      runSetupCheck(input, "s".repeat(32), fetcher),
    ).rejects.toMatchObject({ code: "check_failed" });
    expect(JSON.parse(calls[0]!)).toEqual({
      contract: "open-trestle/setup-check-request",
      schema_version: 1,
      plan_identity: input.plan_identity,
      key: input.key,
      confirmation: "run webhook_validated",
      approve_webhook_authority_identity:
        input.approve_webhook_authority_identity,
      github_webhook_key_id: input.github_webhook_key_id,
      approved_by: input.approved_by,
    });
    expect(calls[0]).not.toContain("secret");
    await expect(
      runSetupCheck(
        { ...input, github_webhook_key_id: " bad " },
        "s".repeat(32),
        fetcher,
      ),
    ).rejects.toMatchObject({ code: "invalid_scope" });
    expect(calls).toHaveLength(1);
  });

  it("requires database authority exactly for PostgreSQL runtime status", () => {
    const status = {
      ...runtimeStatus,
      configuration: {
        ...runtimeStatus.configuration,
        metadata_backend: "postgres" as const,
        database_authority_identity: "d".repeat(64),
        rate_limit_backend: "postgres" as const,
        rate_limit_authority_identity: "e".repeat(64),
      },
    };
    expect(
      parseRuntimeStatusEnvelope(
        {
          contract: "open-trestle/runtime-status-response",
          schema_version: 1,
          request_id: "request-a",
          status,
        },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).toEqual(status);
    const missing = {
      ...status,
      configuration: { ...status.configuration },
    } as any;
    delete missing.configuration.database_authority_identity;
    delete missing.configuration.rate_limit_authority_identity;
    expect(() =>
      parseRuntimeStatusEnvelope(
        {
          contract: "open-trestle/runtime-status-response",
          schema_version: 1,
          request_id: "request-a",
          status: missing,
        },
        { tenant: "tenant-a", repository: "repo-a" },
      ),
    ).toThrow(ApiError);
  });
});
