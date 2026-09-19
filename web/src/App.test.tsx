import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import {
  ApiError,
  fetchDiagnostics,
  fetchRun,
  fetchRuntimeStatus,
  fetchSetupSession,
  initializeSetup,
  parseSetupSession,
  runSetupCheck,
} from "./api";
import { setupTestPlan } from "./setup-test-data";
import type { DiagnosticSet, SetupPlan } from "./types";
vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    fetchRun: vi.fn(),
    fetchDiagnostics: vi.fn(),
    fetchRuntimeStatus: vi.fn(),
    fetchSetupSession: vi.fn(),
    initializeSetup: vi.fn(),
    runSetupCheck: vi.fn(),
  };
});
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
function capturedPlan(wire: string): SetupPlan {
  return parseSetupSession({
    contract: "open-trestle/setup-session",
    schema_version: 1,
    initialized: true,
    plan: JSON.parse(wire),
  }).plan!;
}
function currentPermissionPlan() {
  return capturedPlan(currentPendingWire);
}
function currentWebhookPlan() {
  return capturedPlan(currentPermissionPassedWire);
}
function historicalPermissionPlan(ready: boolean) {
  return capturedPlan(ready ? historicalReadyWire : historicalPendingWire);
}

const digest = "a".repeat(64);
const receipt = {
  contract: "open-trestle/review-run-receipt" as const,
  schema_version: 1 as const,
  identity: digest,
  plan_identity: digest,
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  review_run_id: "run-a",
  status: "active" as const,
  revision: 4,
  head_identity: digest,
  last_occurred_at_milliseconds: 1000,
  output_identity: "",
  failure: "" as const,
  tasks: [
    {
      key: "source",
      task_identity: digest,
      input_identity: digest,
      handler_identity: digest,
      kind: "acquire_source" as const,
      required: true,
      status: "succeeded" as const,
      attempts: 1,
      max_attempts: 1,
      lease_expires_at_milliseconds: 0,
      output_identity: digest,
      failure: "" as const,
      retry_at_milliseconds: 0,
    },
  ],
};

const runtimeStatus = {
  contract: "open-trestle/runtime-status" as const,
  schema_version: 1 as const,
  identity: "b".repeat(64),
  configuration_identity: "c".repeat(64),
  tenant_id: "tenant-a",
  repository_id: "repo-a",
  observed_at: "2026-09-03T12:00:00Z",
  ready: true,
  configuration: {
    tenant_id: "tenant-a",
    repository_ids: ["repo-a"],
    metadata_backend: "local" as const,
    artifact_backend: "local" as const,
    artifact_protection: "process_private" as const,
    notification_backend: "process_local" as const,
    rate_limit_backend: "process_local" as const,
    review_mode: "advisory" as const,
    webhook_ingress: true,
    local_workers: false,
    publication_enabled: false,
    publication_fence_verified: false,
    route_count: 0,
    handlers: [],
  },
  components: [{ name: "task_notifications", state: "ready" as const }],
};

describe("console", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.mocked(fetchRun).mockReset();
    vi.mocked(fetchDiagnostics).mockReset();
    vi.mocked(fetchRuntimeStatus).mockReset();
    vi.mocked(fetchSetupSession).mockReset();
    vi.mocked(initializeSetup).mockReset();
    vi.mocked(runSetupCheck).mockReset();
    window.history.replaceState({}, "", "/console/");
    vi.mocked(fetchRuntimeStatus).mockRejectedValue(
      new Error("not authorized"),
    );
  });
  it("starts with a scoped connection form and does not persist tokens", () => {
    render(<App />);
    expect(
      screen.getByRole("heading", { name: "Locate a review run" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Access token")).toHaveAttribute(
      "autocomplete",
      "off",
    );
    expect(sessionStorage.getItem("open-trestle-token")).toBeNull();
  });
  it("renders exact run and task state", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Run active" }),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText("source")).toBeInTheDocument();
    expect(screen.getByText("succeeded")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: `Copy Run receipt: ${digest}` }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Findings n\/a/i }),
    ).toBeInTheDocument();
    expect(sessionStorage.getItem("open-trestle-scope")).toContain("tenant-a");
    expect(sessionStorage.getItem("open-trestle-token")).toBeNull();
  });

  it("discloses exact verified finding evidence lineage", async () => {
    const findingIdentity = "d".repeat(64);
    const sourceIdentity = "e".repeat(64);
    const fingerprint = "f".repeat(64);
    const evidenceReference = "evidence-authorization-84";
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
      contract: "open-trestle/review-diagnostic-set",
      schema_version: 1,
      identity: "b".repeat(64),
      tenant_id: "tenant-a",
      repository_id: "repo-a",
      review_run_id: "run-a",
      snapshot_identity: "1".repeat(64),
      head_revision: "2".repeat(40),
      verified_set_identity: "3".repeat(64),
      findings: [
        {
          identity: findingIdentity,
          source_identity: sourceIdentity,
          fingerprint,
          title: "Authorization check can be bypassed",
          message: "Move the capability check ahead of the early return.",
          severity: "error",
          path: "internal/access/policy.go",
          start_line: 84,
          end_line: 91,
          evidence_ids: [evidenceReference],
        },
      ],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Run active" });
    fireEvent.click(screen.getByRole("button", { name: /Findings 1/i }));
    const summary = await screen.findByText("Inspect evidence");
    const details = summary.closest("details");
    expect(details).not.toHaveAttribute("open");
    fireEvent.click(summary);
    expect(details).toHaveAttribute("open");
    for (const [label, identity] of [
      ["Diagnostic identity", findingIdentity],
      ["Source finding identity", sourceIdentity],
      ["Finding fingerprint", fingerprint],
      ["Evidence reference 1", evidenceReference],
    ])
      expect(
        screen.getByRole("button", { name: `Copy ${label}: ${identity}` }),
      ).toBeInTheDocument();
    const originalClipboard = navigator.clipboard;
    const writeText = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("permission denied with secret detail"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Diagnostic identity: ${findingIdentity}`,
      }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent("Copied");
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Source finding identity: ${sourceIdentity}`,
      }),
    );
    expect(await screen.findByText("Copy failed")).toHaveAttribute(
      "role",
      "status",
    );
    expect(writeText).toHaveBeenNthCalledWith(1, findingIdentity);
    expect(writeText).toHaveBeenNthCalledWith(2, sourceIdentity);
    expect(screen.queryByText(/permission denied/i)).not.toBeInTheDocument();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: originalClipboard,
    });
  });

  it("renders incomplete candidate and source coverage without implying approval", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
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
        candidate_count: 2,
        verified_count: 0,
        rejected_count: 1,
        inconclusive_count: 1,
      },
      source_coverage: {
        verification_context_identity: "4".repeat(64),
        analyzed_count: 173,
        selected_count: 1,
        omitted_count: 172,
        omissions: [
          { reason: "selection_limit", count: 170 },
          { reason: "unsupported", count: 2 },
        ],
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
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Run active" });
    fireEvent.click(screen.getByRole("button", { name: /Findings 0/i }));
    expect(
      await screen.findByRole("heading", { name: "Human review queue" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Review coverage" }),
    ).toBeInTheDocument();
    expect(screen.getByText("1 rejected")).toBeInTheDocument();
    expect(screen.getByText("1 inconclusive")).toBeInTheDocument();
    expect(screen.getByText("173 sources analyzed")).toBeInTheDocument();
    expect(screen.getByText("1 selected for model review")).toBeInTheDocument();
    expect(
      screen.getByText("172 omitted from model context"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Source coverage is incomplete/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Omission reasons: 170 selection limit, 2 unsupported/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Cleared gate: Static debug output passed/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Cleared for this exact rule only/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/does not approve the change/i),
    ).toBeInTheDocument();
    expect(
      screen
        .getByRole("heading", { name: "No verified findings" })
        .closest("section"),
    ).not.toHaveClass("verified");
  });

  it("does not present a failed deterministic check as a clean empty state", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockResolvedValue({
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
          state: "failed",
          applicable_files: 1,
          applicable_ranges: 1,
          checked_files: 1,
          checked_ranges: 1,
          matches: 1,
        },
      ],
      findings: [],
    });
    render(<App />);
    for (const [name, value] of [
      ["Tenant", "tenant-a"],
      ["Repository", "repo-a"],
      ["Run", "run-a"],
      ["Access token", "x".repeat(32)],
    ] as const)
      fireEvent.change(screen.getByLabelText(name), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Run active" });
    fireEvent.click(screen.getByRole("button", { name: /Findings 0/i }));
    expect(
      await screen.findByText(/Failed check: Static debug output failed/i),
    ).toBeInTheDocument();
    const empty = screen
      .getByRole("heading", { name: "No verified findings" })
      .closest("section");
    expect(empty).not.toHaveClass("verified");
    expect(empty).toHaveTextContent(/deterministic check requires review/i);
  });

  it.each([false, true])(
    "does not dispatch with a disconnected token after late diagnostics (reconnect: %s)",
    async (reconnect) => {
      let resolveDiagnostics!: (value: DiagnosticSet) => void;
      const lateDiagnostics: DiagnosticSet = {
        contract: "open-trestle/review-diagnostic-set",
        schema_version: 1,
        identity: digest,
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        review_run_id: "run-a",
        snapshot_identity: digest,
        head_revision: "abc123",
        verified_set_identity: digest,
        findings: [],
      };
      vi.mocked(fetchRun).mockResolvedValueOnce(receipt);
      vi.mocked(fetchDiagnostics).mockReturnValueOnce(
        new Promise((resolve) => {
          resolveDiagnostics = resolve;
        }),
      );
      render(<App />);
      for (const [name, value] of [
        ["Tenant", "tenant-a"],
        ["Repository", "repo-a"],
        ["Run", "run-a"],
        ["Access token", "x".repeat(32)],
      ] as const)
        fireEvent.change(screen.getByLabelText(name), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
      await screen.findByRole("heading", { name: "Run active" });
      expect(fetchDiagnostics).toHaveBeenCalledTimes(1);
      fireEvent.click(screen.getByRole("button", { name: "Change scope" }));
      if (reconnect) {
        vi.mocked(fetchRun).mockResolvedValueOnce({
          ...receipt,
          tenant_id: "tenant-b",
          repository_id: "repo-b",
          review_run_id: "run-b",
        });
        vi.mocked(fetchDiagnostics).mockRejectedValueOnce(
          new Error("not ready"),
        );
        for (const [name, value] of [
          ["Tenant", "tenant-b"],
          ["Repository", "repo-b"],
          ["Run", "run-b"],
          ["Access token", "y".repeat(32)],
        ] as const)
          fireEvent.change(screen.getByLabelText(name), { target: { value } });
        fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
        await waitFor(() =>
          expect(fetchRuntimeStatus).toHaveBeenCalledTimes(1),
        );
      }
      await act(async () => resolveDiagnostics(lateDiagnostics));
      if (reconnect) {
        expect(fetchRuntimeStatus).toHaveBeenCalledExactlyOnceWith(
          { tenant: "tenant-b", repository: "repo-b", run: "run-b" },
          "y".repeat(32),
        );
        expect(screen.getByText("run-b")).toBeInTheDocument();
      } else {
        expect(fetchRuntimeStatus).not.toHaveBeenCalled();
        expect(
          screen.getByRole("heading", { name: "Locate a review run" }),
        ).toBeInTheDocument();
      }
    },
  );
  it.each(["SecurityError", "QuotaExceededError"])(
    "connects and disconnects when optional scope storage throws %s",
    async (name) => {
      const write = vi
        .spyOn(Object.getPrototypeOf(sessionStorage), "setItem")
        .mockImplementation(() => {
          throw new DOMException("Storage unavailable", name);
        });
      try {
        vi.mocked(fetchRun).mockResolvedValue(receipt);
        vi.mocked(fetchDiagnostics).mockResolvedValue({
          contract: "open-trestle/review-diagnostic-set",
          schema_version: 1,
          identity: digest,
          tenant_id: "tenant-a",
          repository_id: "repo-a",
          review_run_id: "run-a",
          snapshot_identity: digest,
          head_revision: "abc123",
          verified_set_identity: digest,
          findings: [],
        });
        vi.mocked(fetchRuntimeStatus).mockResolvedValue(runtimeStatus);
        render(<App />);
        for (const [label, value] of [
          ["Tenant", "tenant-a"],
          ["Repository", "repo-a"],
          ["Run", "run-a"],
          ["Access token", "x".repeat(32)],
        ] as const)
          fireEvent.change(screen.getByLabelText(label), { target: { value } });
        fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
        await screen.findByRole("button", { name: /Runtime ready/i });
        expect(fetchDiagnostics).toHaveBeenCalledTimes(1);
        expect(fetchRuntimeStatus).toHaveBeenCalledTimes(1);
        expect(
          screen.getByRole("button", { name: /Findings 0/i }),
        ).toBeInTheDocument();
        expect(screen.queryByRole("alert")).not.toBeInTheDocument();
        expect(write).toHaveBeenCalledExactlyOnceWith(
          "open-trestle-scope",
          JSON.stringify({
            tenant: "tenant-a",
            repository: "repo-a",
            run: "run-a",
          }),
        );
        expect(sessionStorage.length).toBe(0);
        fireEvent.click(screen.getByRole("button", { name: "Change scope" }));
        expect(screen.getByLabelText("Access token")).toHaveValue("");
        expect(sessionStorage.length).toBe(0);
      } finally {
        write.mockRestore();
      }
    },
  );
  it("copies exact runtime handler identities even when their visible ends match", async () => {
    const handlers = [
      { kind: "acquire_source" as const, identity: "1".repeat(64) },
      {
        kind: "build_change" as const,
        identity: "1".repeat(10) + "2".repeat(46) + "1".repeat(8),
      },
    ];
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRuntimeStatus).mockResolvedValue({
      ...runtimeStatus,
      configuration: {
        ...runtimeStatus.configuration,
        handlers,
      },
    });
    const originalClipboard = navigator.clipboard;
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    try {
      render(<App />);
      for (const [name, value] of [
        ["Tenant", "tenant-a"],
        ["Repository", "repo-a"],
        ["Run", "run-a"],
        ["Access token", "x".repeat(32)],
      ] as const)
        fireEvent.change(screen.getByLabelText(name), { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
      fireEvent.click(
        await screen.findByRole("button", { name: /Runtime ready/i }),
      );
      const section = screen
        .getByRole("heading", { name: "Handler authority" })
        .closest("section")!;
      for (const { kind, identity } of handlers) {
        expect(within(section).getByText(identity)).toHaveClass("sr-only");
        const button = within(section).getByRole("button", {
          name: `Copy ${kind.replaceAll("_", " ")}: ${identity}`,
        });
        button.focus();
        expect(button).toHaveFocus();
        fireEvent.click(button);
        await waitFor(() =>
          expect(writeText).toHaveBeenLastCalledWith(identity),
        );
      }
      expect(writeText).toHaveBeenCalledTimes(2);
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  });
  it("renders authenticated content-free runtime status", async () => {
    vi.mocked(fetchRun).mockResolvedValue(receipt);
    vi.mocked(fetchDiagnostics).mockRejectedValue(new Error("not ready"));
    vi.mocked(fetchRuntimeStatus).mockResolvedValue(runtimeStatus);
    render(<App />);
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText("Run"), {
      target: { value: "run-a" },
    });
    fireEvent.change(screen.getByLabelText("Access token"), {
      target: { value: "x".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Connect to run" }));
    await screen.findByRole("heading", { name: "Run active" });
    fireEvent.click(screen.getByRole("button", { name: /Runtime ready/i }));
    expect(
      await screen.findByRole("heading", { name: "Runtime state" }),
    ).toBeInTheDocument();
    expect(screen.getByText("task notifications")).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: `Copy Configuration: ${"c".repeat(64)}`,
      }),
    ).toBeInTheDocument();
  });

  it("creates a safe setup plan only after explicit confirmation", async () => {
    window.history.replaceState({}, "", "/console/setup");
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: false,
    });
    vi.mocked(initializeSetup).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan: setupTestPlan(),
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    expect(
      await screen.findByRole("heading", { name: "Choose a safe baseline" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Tenant"), {
      target: { value: "tenant-a" },
    });
    fireEvent.change(screen.getByLabelText("Repository"), {
      target: { value: "repo-a" },
    });
    fireEvent.change(screen.getByLabelText(/Recovery owner/), {
      target: { value: "owner" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review plan creation" }),
    );
    expect(initializeSetup).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: "Create setup plan" }),
    ).toHaveFocus();
    fireEvent.click(screen.getByRole("button", { name: "Create setup plan" }));
    expect(
      await screen.findByRole("heading", { name: "local single node" }),
    ).toBeInTheDocument();
    expect(initializeSetup).toHaveBeenCalledWith(
      {
        profile: "local_single_node",
        tenant_id: "tenant-a",
        repository_id: "repo-a",
        recovery_owner: "owner",
      },
      "s".repeat(32),
    );
    expect(sessionStorage.getItem("open-trestle-setup-token")).toBeNull();
  });
  it("reports setup identity clipboard rejection", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    const originalClipboard = navigator.clipboard;
    const writeText = vi
      .fn()
      .mockRejectedValue(new Error("permission denied with secret detail"));
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", {
        name: `Copy Plan identity: ${plan.identity}`,
      }),
    );
    expect(await screen.findByText("Copy failed")).toHaveAttribute(
      "role",
      "status",
    );
    expect(writeText).toHaveBeenCalledWith(plan.identity);
    expect(screen.queryByText(/permission denied/i)).not.toBeInTheDocument();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: originalClipboard,
    });
  });

  it("requires a second confirmation before writing a setup receipt", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const initial = setupTestPlan(),
      next = setupTestPlan(true),
      receipt = next.receipts[0]!;
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan: initial,
    });
    vi.mocked(runSetupCheck).mockResolvedValue({
      contract: "open-trestle/setup-check-result",
      schema_version: 1,
      plan: next,
      receipt,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", {
        name: /observer credential posture validated/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(runSetupCheck).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", {
        name: "Run observer credential posture validated",
      }),
    ).toHaveFocus();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Run observer credential posture validated",
      }),
    );
    expect(
      await screen.findByText("Check completed: passed."),
    ).toBeInTheDocument();
    expect(runSetupCheck).toHaveBeenCalledWith(
      {
        plan_identity: initial.identity,
        key: "observer_credential_posture_validated",
      },
      "s".repeat(32),
    );
  });

  it("does not restore setup state from a late check response", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const initial = setupTestPlan(),
      next = setupTestPlan(true),
      receipt = next.receipts[0]!;
    let resolveCheck!: (value: {
      contract: "open-trestle/setup-check-result";
      schema_version: 1;
      plan: SetupPlan;
      receipt: typeof receipt;
    }) => void;
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan: initial,
    });
    vi.mocked(runSetupCheck).mockReturnValue(
      new Promise((resolve) => {
        resolveCheck = resolve;
      }),
    );
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", {
        name: /observer credential posture validated/i,
      }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Run observer credential posture validated",
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Change token" }));
    resolveCheck({
      contract: "open-trestle/setup-check-result",
      schema_version: 1,
      plan: next,
      receipt,
    });
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Open protected setup" }),
      ).toBeInTheDocument(),
    );
  });

  it("describes restored unsupported outcomes without calling them pending", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "local_inference_validated"
        ? {
            ...requirement,
            key: "no_egress_validated",
            state: "passed",
            checker_identity: "1".repeat(64),
            evidence_identity: "8".repeat(64),
            receipt_identity: "9".repeat(64),
            checked_at: "2026-09-03T12:00:02Z",
          }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", {
        name: /no egress validated/i,
      }),
    );
    expect(
      screen.getByText(/completed through another setup surface/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/it remains pending/i)).not.toBeInTheDocument();
  });

  it("requires explicit local authority and shows bounded backup claims", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const initial = setupTestPlan(),
      next = setupTestPlan(true),
      receipt = next.receipts[0]!;
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan: initial,
    });
    vi.mocked(runSetupCheck).mockResolvedValue({
      contract: "open-trestle/setup-check-result",
      schema_version: 1,
      plan: next,
      receipt,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", { name: /local administrator validated/i }),
    );
    await screen.findByRole("heading", {
      name: "local administrator validated",
    });
    expect(
      screen.getByRole("textbox", { name: /Approved recovery owner/i }),
    ).toHaveValue("");
    fireEvent.change(
      screen.getByRole("textbox", { name: /Approved recovery owner/i }),
      {
        target: { value: "owner" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Run local administrator validated" }),
    );
    await screen.findByText("Check completed: passed.");
    expect(runSetupCheck).toHaveBeenCalledWith(
      {
        plan_identity: initial.identity,
        key: "local_administrator_validated",
        approved_by: "owner",
      },
      "s".repeat(32),
    );
  });
  it("explains that a protected backup snapshot is not independent recovery proof", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const initial = setupTestPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan: initial,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(screen.getByRole("button", { name: /backup validated/i }));
    await screen.findByRole("heading", { name: "backup validated" });
    expect(
      screen.getByRole("textbox", { name: /Backup snapshot path/i }),
    ).toHaveValue("");
    expect(
      screen.getByText(
        /does not prove independent media or a successful disaster recovery exercise/i,
      ),
    ).toBeInTheDocument();
  });

  it("keeps local inference explicit, policy-gated, and non-publishing", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", { name: /local inference validated/i }),
    );
    await screen.findByRole("heading", { name: "local inference validated" });
    expect(screen.getByText(/at most two fixed probes/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Pass the exact policy validation check/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/no retry or remote fallback/i),
    ).toBeInTheDocument();
    for (const [name, value] of [
      [/Route inventory path/i, "/routes"],
      [/Runtime policy path/i, "/policy"],
      [/Inventory identity/i, "1".repeat(64)],
      [/Runtime policy identity/i, "2".repeat(64)],
      [/Review policy identity/i, "3".repeat(64)],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
  });

  it("enables confirmed local inference only after policy evidence", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "policy_validated"
        ? { ...requirement, state: "passed" }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "local single node" });
    fireEvent.click(
      screen.getByRole("button", { name: /local inference validated/i }),
    );
    await screen.findByRole("heading", { name: "local inference validated" });
    for (const [name, value] of [
      [/Route inventory path/i, "/routes"],
      [/Runtime policy path/i, "/policy"],
      [/Inventory identity/i, "1".repeat(64)],
      [/Runtime policy identity/i, "2".repeat(64)],
      [/Review policy identity/i, "3".repeat(64)],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByRole("button", { name: "Run local inference validated" }),
    ).toHaveFocus();
  });

  it("requires an explicit non-secret PostgreSQL authority approval", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "controlled_hybrid";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "state_storage_posture_validated"
        ? { ...requirement, key: "postgres_storage_validated" }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(
      screen.getByRole("button", { name: /postgres storage validated/i }),
    );
    await screen.findByRole("heading", { name: "postgres storage validated" });
    expect(
      screen.getByText(/reads the DSN only on the server/i),
    ).toBeInTheDocument();
    const authority = screen.getByRole("textbox", {
        name: /PostgreSQL authority identity/i,
      }),
      approved = screen.getByRole("textbox", {
        name: /PostgreSQL approved by/i,
      });
    expect(authority).toHaveValue("");
    expect(approved).toHaveValue("");
    fireEvent.change(authority, { target: { value: "a".repeat(64) } });
    fireEvent.change(approved, { target: { value: "owner" } });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
  });
  it("requires explicit KMS authority before the bounded secret-backend check", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "controlled_hybrid";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "state_storage_posture_validated"
        ? { ...requirement, key: "secret_backend_validated" }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(
      screen.getByRole("button", { name: /secret backend validated/i }),
    );
    await screen.findByRole("heading", { name: "secret backend validated" });
    expect(screen.getByText(/performs no S3 operation/i)).toBeInTheDocument();
    for (const [name, value] of [
      [/KMS authority identity/i, "a".repeat(64)],
      [/^KMS region$/i, "us-east-1"],
      [/Tenant KMS key ARN/i, "arn:aws:kms:us-east-1:123456789012:key/example"],
      [/KMS approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(screen.getByRole("textbox", { name: /KMS endpoint/i })).toHaveValue(
      "",
    );
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(screen.getByText(/two bounded KMS operations/i)).toBeInTheDocument();
  });
  it("requires explicit authority before effectful envelope-storage conformance", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "controlled_hybrid";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "state_storage_posture_validated"
        ? { ...requirement, key: "envelope_storage_validated" }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(
      screen.getByRole("button", { name: /envelope storage validated/i }),
    );
    await screen.findByRole("heading", { name: "envelope storage validated" });
    expect(
      screen.getByText(/partial failure can leave one encrypted object/i),
    ).toBeInTheDocument();
    for (const [name, value] of [
      [/Envelope storage authority identity/i, "a".repeat(64)],
      [/^S3 endpoint$/i, "https://s3.example"],
      [/^S3 region$/i, "us-east-1"],
      [/^S3 bucket$/i, "artifacts"],
      [/S3 object prefix/i, "reviews"],
      [/^KMS region$/i, "us-east-1"],
      [/Tenant KMS key ARN/i, "arn:aws:kms:us-east-1:123456789012:key/example"],
      [/Envelope storage approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(/bounded KMS operations plus the S3 writes/i),
    ).toBeInTheDocument();
  });
  it("authorizes exact remote configuration without reading provider credentials", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "controlled_hybrid";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    plan.requirements = plan.requirements.map((requirement) =>
      requirement.key === "state_storage_posture_validated"
        ? {
            ...requirement,
            key: "remote_provider_authorized",
            source: "authorization",
          }
        : requirement,
    );
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(
      screen.getByRole("button", { name: /remote provider authorized/i }),
    );
    await screen.findByRole("heading", { name: "remote provider authorized" });
    expect(
      screen.getByText(
        /does not read credential values or contact a provider/i,
      ),
    ).toBeInTheDocument();
    for (const [name, value] of [
      [/Route inventory path/i, "/routes"],
      [/Runtime policy path/i, "/policy"],
      [/^Inventory identity$/i, "1".repeat(64)],
      [/Runtime policy identity/i, "2".repeat(64)],
      [/Review policy identity/i, "3".repeat(64)],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(
        /will not read provider credentials or make a network request/i,
      ),
    ).toBeInTheDocument();
  });
  it("inspects exact GitHub permissions without exposing the setup token", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = currentPermissionPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(
      screen.getByRole("button", {
        name: /integration permissions validated/i,
      }),
    );
    await screen.findByRole("heading", {
      name: "integration permissions validated",
    });
    expect(
      screen.getByText(/retains content-free owner records/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: /setup token/i }),
    ).not.toBeInTheDocument();
    for (const name of [
      /GitHub API endpoint/i,
      /GitHub API version/i,
      /GitHub installation ID/i,
      /GitHub repository full name/i,
      /private key/i,
    ])
      expect(screen.queryByRole("textbox", { name })).not.toBeInTheDocument();
    for (const [name, value] of [
      [/Integration permission authority identity/i, "a".repeat(64)],
      [/GitHub source broker authority identity/i, "b".repeat(64)],
      [/Integration approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
    const consent = screen.getByRole("button", {
      name: "Allow GitHub installation token creation: no",
    });
    expect(consent).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(consent);
    fireEvent.change(
      screen.getByRole("textbox", { name: /Integration approved by/i }),
      {
        target: { value: "another-owner" },
      },
    );
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
    fireEvent.change(
      screen.getByRole("textbox", { name: /Integration approved by/i }),
      {
        target: { value: plan.recovery_owner },
      },
    );
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(
        /create GitHub installation token and run integration_permissions_validated/,
      ),
    ).toBeInTheDocument();
    expect(runSetupCheck).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Go back" }));
    expect(runSetupCheck).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    fireEvent.change(
      screen.getByRole("textbox", {
        name: /GitHub source broker authority identity/i,
      }),
      {
        target: { value: "c".repeat(64) },
      },
    );
    expect(
      screen.queryByRole("region", { name: /Write one integration/i }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    fireEvent.click(consent);
    expect(
      screen.queryByRole("region", { name: /Write one integration/i }),
    ).not.toBeInTheDocument();
    expect(runSetupCheck).not.toHaveBeenCalled();
    fireEvent.click(consent);
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    vi.mocked(runSetupCheck).mockRejectedValueOnce(new ApiError("stale_plan"));
    fireEvent.click(
      screen.getByRole("button", {
        name: "Run integration permissions validated",
      }),
    );
    await screen.findByText(/The setup plan changed. Inspect it again/i);
    expect(runSetupCheck).toHaveBeenCalledExactlyOnceWith(
      {
        plan_identity: plan.identity,
        key: "integration_permissions_validated",
        approve_integration_permission_authority_identity: "a".repeat(64),
        approve_github_source_broker_authority_identity: "c".repeat(64),
        allow_github_installation_token_creation: true,
        approved_by: "owner",
      },
      "s".repeat(32),
    );
    expect(
      screen.queryByRole("region", { name: /Write one integration/i }),
    ).not.toBeInTheDocument();
  });
  it("runs shared rate-limit conformance only after PostgreSQL evidence", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "kubernetes_ha";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    const base = plan.requirements[0]!;
    plan.requirements = [
      {
        ...base,
        key: "postgres_storage_validated",
        source: "probe",
        state: "passed",
      },
      {
        ...base,
        key: "shared_rate_limit_validated",
        source: "probe",
        state: "pending",
        receipt_identity: "",
        evidence_identity: "",
      },
    ];
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "kubernetes ha" });
    fireEvent.click(
      screen.getByRole("button", { name: /shared rate limit validated/i }),
    );
    await screen.findByRole("heading", { name: "shared rate limit validated" });
    expect(
      screen.getByText(/two independent limiter instances/i),
    ).toBeInTheDocument();
    for (const [name, value] of [
      [/Shared rate-limit authority identity/i, "a".repeat(64)],
      [/PostgreSQL database authority identity/i, "b".repeat(64)],
      [/Shared rate-limit approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(/bounded shared-database quota cycle/i),
    ).toBeInTheDocument();
  });

  it("verifies an opaque signed bundle without importing it", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "air_gapped";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "local",
      artifact_backend: "local",
      artifact_protection: "process_private",
      notification_backend: "process_local",
      inference: "local_only",
      egress: "denied",
      integration: "offline_bundle",
      max_model_request_cost_micro_usd: 0,
    };
    const base = plan.requirements[0]!;
    plan.requirements = [
      {
        ...base,
        key: "signed_bundle_validated",
        source: "probe",
        state: "pending",
        receipt_identity: "",
        evidence_identity: "",
      },
    ];
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "air gapped" });
    fireEvent.click(
      screen.getByRole("button", { name: /signed bundle validated/i }),
    );
    await screen.findByRole("heading", { name: "signed bundle validated" });
    expect(screen.getByText(/streams the opaque file/i)).toBeInTheDocument();
    for (const [name, value] of [
      [/Signed bundle authority identity/i, "a".repeat(64)],
      [/Bundle path/i, "relative.bundle"],
      [/Bundle SHA-256/i, "b".repeat(64)],
      [/Bundle bytes/i, "1024"],
      [/Ed25519 public key/i, "c".repeat(64)],
      [/Ed25519 signature/i, "d".repeat(128)],
      [/Signed bundle approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", { name: /Bundle path/i }), {
      target: { value: "/private/release.bundle" },
    });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(/stream and verify the exact opaque file/i),
    ).toBeInTheDocument();
  });

  it("runs replica reconciliation only after PostgreSQL evidence", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = setupTestPlan();
    plan.profile = "kubernetes_ha";
    plan.posture = {
      ...plan.posture,
      metadata_backend: "postgres",
      artifact_backend: "s3",
      artifact_protection: "envelope_encrypted",
      notification_backend: "postgres",
      inference: "approved_remote",
      egress: "allowlisted",
      integration: "least_privilege_scm",
      max_model_request_cost_micro_usd: 100000,
    };
    const base = plan.requirements[0]!;
    plan.requirements = [
      {
        ...base,
        key: "postgres_storage_validated",
        source: "probe",
        state: "passed",
      },
      {
        ...base,
        key: "replica_reconciliation_validated",
        source: "probe",
        state: "pending",
        receipt_identity: "",
        evidence_identity: "",
      },
    ];
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "kubernetes ha" });
    fireEvent.click(
      screen.getByRole("button", { name: /replica reconciliation validated/i }),
    );
    await screen.findByRole("heading", {
      name: "replica reconciliation validated",
    });
    expect(
      screen.getByText(/two independent runtime instances/i),
    ).toBeInTheDocument();
    for (const [name, value] of [
      [/Replica reconciliation authority identity/i, "a".repeat(64)],
      [/PostgreSQL database authority identity/i, "b".repeat(64)],
      [/Replica reconciliation approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(/bounded shared-metadata reconciliation cycle/i),
    ).toBeInTheDocument();
  });

  it("keeps current webhook pending until the current permission receipt passes", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = currentPermissionPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    expect(screen.queryByText(/Historical catalog:/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /webhook validated/i }));
    for (const [name, value] of [
      [/Webhook authority identity/i, "a".repeat(64)],
      [/GitHub webhook key ID/i, "primary-2026"],
      [/Webhook approved by/i, plan.recovery_owner],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
    expect(runSetupCheck).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    "blocks historical integration and webhook actions (Ready=%s)",
    async (ready) => {
      window.history.replaceState({}, "", "/console/setup");
      const plan = historicalPermissionPlan(ready);
      vi.mocked(fetchSetupSession).mockResolvedValue({
        contract: "open-trestle/setup-session",
        schema_version: 1,
        initialized: true,
        plan,
      });
      render(<App />);
      fireEvent.change(await screen.findByLabelText("Setup token"), {
        target: { value: "s".repeat(32) },
      });
      fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
      await screen.findByText(
        /Historical catalog: Ready and receipts are historical/i,
      );
      expect(
        screen.getByText(/fresh protected state path/i),
      ).toBeInTheDocument();
      for (const key of [
        "integration permissions validated",
        "webhook validated",
      ]) {
        fireEvent.click(screen.getByRole("button", { name: new RegExp(key) }));
        await screen.findByRole("heading", { name: key });
        const fields = key.startsWith("integration")
          ? ([
              [/Integration permission authority identity/i, "a".repeat(64)],
              [/GitHub source broker authority identity/i, "b".repeat(64)],
              [/Integration approved by/i, plan.recovery_owner],
            ] as const)
          : ([
              [/Webhook authority identity/i, "a".repeat(64)],
              [/GitHub webhook key ID/i, "primary-2026"],
              [/Webhook approved by/i, plan.recovery_owner],
            ] as const);
        for (const [name, value] of fields)
          fireEvent.change(screen.getByRole("textbox", { name }), {
            target: { value },
          });
        if (key.startsWith("integration"))
          fireEvent.click(
            screen.getByRole("button", {
              name: "Allow GitHub installation token creation: no",
            }),
          );
        expect(
          screen.queryByRole("button", { name: "Review receipt write" }),
        ).not.toBeInTheDocument();
      }
      expect(runSetupCheck).not.toHaveBeenCalled();
      expect(
        screen.getByRole("heading", { name: "Receipt lineage" }),
      ).toBeInTheDocument();
    },
  );

  it("blocks historical pending webhook despite a passed legacy permission receipt", async () => {
    // Exact native pre-change fixtures[2].plan.bytes from legacy-capture/manifest.json.
    // SHA256 b0f09483ce6e7db0ac31c389ac4cb2d430408f7ec5b0d4dec550d67479aa5766; no regeneration or relabeling.
    const wire = `{"contract":"open-trestle/setup-plan","schema_version":1,"identity":"443a6272bcb6d541f6607834dbcbb718313f1d813f6ed0d15dcbd32a0228b0b8","previous_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","checker_catalog_identity":"3a88cb6db2d7a6b3b9eae8aa36e4ca2a0914e6ad5138bb9e5249607d12c49b1f","checker_authorities":[{"key":"backup_validated","checker_identity":"03a4d428f289ba85dba8c4f1b7ddfafc74583d9309864f36cc6ef8926616b679"},{"key":"dry_run_validated","checker_identity":"10304a30edd798790388e923d73df4115b8526231641db5b13dee9d088f938df"},{"key":"envelope_storage_validated","checker_identity":"a7366f408e306dd70702319bfad8333f71e7e92b97604d69be936291a0b98ceb"},{"key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b"},{"key":"local_administrator_validated","checker_identity":"f3832f5d85d7774290f8b6c88a634ec956e68ced3198fd6fca64a9b6f99ced89"},{"key":"observer_credential_posture_validated","checker_identity":"4af5a2fcecd69ec07da6ffb696215820c2b84a225340953f68f5a126e52cf542"},{"key":"policy_validated","checker_identity":"5694cd4de9ea61bc97b9cdcfa651678c23f55e9998e564fea4570585cc8386a4"},{"key":"postgres_storage_validated","checker_identity":"df68a8e3dbe159f168d8464410a5be817e53a0d6870517edde780d374fcb17f0"},{"key":"remote_provider_authorized","checker_identity":"1999eefcbe108499aeeded297b938cbb248e5a14552ebdc697b3e69d7985f4c1"},{"key":"secret_backend_validated","checker_identity":"2ce90162ea0586ca8db04cda4e7a1ee9fc6303e7e2cc77773d36c519785839df"},{"key":"webhook_validated","checker_identity":"94b83acc748c71e3d42ce06632b4abb370f35bbfc2262d2c1e98a223d29fc14e"}],"revision":2,"tenant_id":"pf1-tenant","repository_id":"pf1-repository","recovery_owner":"pf1-owner","profile":"controlled_hybrid","posture":{"metadata_backend":"postgres","artifact_backend":"s3","artifact_protection":"envelope_encrypted","notification_backend":"postgres","inference":"approved_remote","egress":"allowlisted","integration":"least_privilege_scm","max_model_request_cost_micro_usd":100000,"retention_days":30,"provider_fallback_enabled":false,"content_logging_allowed":false,"publication_enabled":false,"dynamic_validation_enabled":false},"requirements":[{"key":"profile_selected","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"scope_valid","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"effect_posture_locked","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"recovery_owner_named","source":"deterministic","state":"passed","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"postgres_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"envelope_storage_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"backup_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"secret_backend_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"local_administrator_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"observer_credential_posture_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"remote_provider_authorized","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"integration_permissions_validated","source":"authorization","state":"passed","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","receipt_identity":"732ca5ba0d984a50dbfcc4c15d38d1c7ab546115b9a811761a4a30cc6a6762ce","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"},{"key":"webhook_validated","source":"probe","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"policy_validated","source":"authorization","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""},{"key":"dry_run_validated","source":"dry_run","state":"pending","checker_identity":"","evidence_identity":"","receipt_identity":"","recovery_action":"","checked_at":""}],"receipts":[{"contract":"open-trestle/setup-check-receipt","schema_version":1,"identity":"732ca5ba0d984a50dbfcc4c15d38d1c7ab546115b9a811761a4a30cc6a6762ce","plan_identity":"f8ceacaddafd1bc9cbeabe52563974cf98797e47f67b3fcbf478b52830731c89","key":"integration_permissions_validated","checker_identity":"cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b","state":"passed","evidence_identity":"764af3d0634054f2e3ab7fe1f7e748181dce796d9bc0e6f8fa64608795c18744","recovery_action":"","checked_at":"2026-09-06T12:00:01Z"}],"status":"incomplete","ready":false,"created_at":"2026-09-06T12:00:00Z","updated_at":"2026-09-06T12:00:01Z"}`;
    const plan = capturedPlan(wire);
    expect(JSON.stringify(plan)).toBe(wire);
    expect(plan.identity).toBe(
      "443a6272bcb6d541f6607834dbcbb718313f1d813f6ed0d15dcbd32a0228b0b8",
    );
    const permission = plan.requirements.find(
      (value) => value.key === "integration_permissions_validated",
    )!;
    expect(permission.state).toBe("passed");
    expect(permission.checker_identity).toBe(
      "cf33c90ab5e11af104ab7c7dc4fba5485bdcf15d99df8155628f0c84e574530b",
    );
    expect(
      plan.receipts.some(
        (receipt) =>
          receipt.identity === permission.receipt_identity &&
          receipt.key === permission.key &&
          receipt.state === "passed",
      ),
    ).toBe(true);
    expect(
      plan.requirements.find((value) => value.key === "webhook_validated"),
    ).toMatchObject({
      state: "pending",
      receipt_identity: "",
      evidence_identity: "",
    });
    window.history.replaceState({}, "", "/console/setup");
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByText(
      /Historical catalog: Ready and receipts are historical/i,
    );
    fireEvent.click(screen.getByRole("button", { name: /webhook validated/i }));
    await screen.findByRole("heading", { name: "webhook validated" });
    for (const [name, value] of [
      [/Webhook authority identity/i, "a".repeat(64)],
      [/GitHub webhook key ID/i, "primary-2026"],
      [/Webhook approved by/i, plan.recovery_owner],
    ] as const) {
      const field = screen.getByRole("textbox", { name });
      fireEvent.change(field, { target: { value } });
      expect(field).toHaveValue(value);
    }
    expect(
      screen.queryByRole("button", { name: "Review receipt write" }),
    ).not.toBeInTheDocument();
    expect(runSetupCheck).not.toHaveBeenCalled();
  });

  it("runs local webhook conformance without exposing the webhook secret", async () => {
    window.history.replaceState({}, "", "/console/setup");
    const plan = currentWebhookPlan();
    vi.mocked(fetchSetupSession).mockResolvedValue({
      contract: "open-trestle/setup-session",
      schema_version: 1,
      initialized: true,
      plan,
    });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Setup token"), {
      target: { value: "s".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Inspect setup" }));
    await screen.findByRole("heading", { name: "controlled hybrid" });
    fireEvent.click(screen.getByRole("button", { name: /webhook validated/i }));
    await screen.findByRole("heading", { name: "webhook validated" });
    expect(screen.getByText(/sends five fixed requests/i)).toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: /webhook secret/i }),
    ).not.toBeInTheDocument();
    for (const [name, value] of [
      [/Webhook authority identity/i, "a".repeat(64)],
      [/GitHub webhook key ID/i, "primary-2026"],
      [/Webhook approved by/i, "owner"],
    ] as const)
      fireEvent.change(screen.getByRole("textbox", { name }), {
        target: { value },
      });
    expect(
      screen.getByRole("button", { name: "Review receipt write" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Review receipt write" }),
    );
    expect(
      screen.getByText(/run the five-request local conformance cycle/i),
    ).toBeInTheDocument();
  });
});
