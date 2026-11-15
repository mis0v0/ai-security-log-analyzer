"use strict";

(() => {
  function create(validateText, isPending) {
  function element(tag, text) { const node = document.createElement(tag); node.textContent = text; return node; }
  const inputModeMapping = document.getElementById("input-mode-mapping");
  const mappingPanel = document.getElementById("json-mapping-panel");
  const mappingText = document.getElementById("json-mapping-text");
  const mappingDiscover = document.getElementById("json-mapping-discover");
  const mappingClear = document.getElementById("json-mapping-clear");
  const mappingFields = document.getElementById("json-mapping-fields");
  const mappingConfirm = document.getElementById("json-mapping-confirm");
  const mappingPreview = document.getElementById("json-mapping-preview");
  const mappingError = document.getElementById("json-mapping-error");
  const mappingStatus = document.getElementById("json-mapping-status");
  const mappingResultNotice = document.getElementById("json-mapping-result-notice");
  const mappingChoices = [
    ["timestamp", "json-map-timestamp", "이벤트 시각"],
    ["source_ip", "json-map-source-ip", "관측된 출발지 IP"],
    ["method", "json-map-method", "HTTP 메서드"],
    ["request_uri", "json-map-request-uri", "원 요청 URI"],
    ["status", "json-map-status", "HTTP 응답 상태"],
  ];
  let mappingKeys = [];
  function mappingFailure(message, focus = true) {
    mappingError.textContent = message;
    mappingError.hidden = false;
    mappingText.setAttribute("aria-invalid", "true");
    if (focus) mappingError.focus();
  }

  function resetMappingChoices() {
    mappingKeys = [];
    mappingFields.disabled = true;
    mappingConfirm.checked = false;
    mappingConfirm.disabled = true;
    mappingPreview.replaceChildren();
    mappingChoices.forEach(([, id]) => {
      const select = document.getElementById(id);
      const placeholder = element("option", "필드를 선택하세요");
      placeholder.value = "";
      select.replaceChildren(placeholder);
      select.value = "";
    });
    mappingError.hidden = true;
    mappingError.textContent = "";
    mappingText.removeAttribute("aria-invalid");
    mappingStatus.textContent = "아직 확인한 필드가 없습니다.";
  }

  function clearMappingInput() {
    mappingText.value = "";
    resetMappingChoices();
  }

  function selectedMapping() {
    return Object.fromEntries(mappingChoices.map(([meaning, id]) => [meaning, document.getElementById(id).value]));
  }

  function mappingSelectionChanged() {
    mappingConfirm.checked = false;
    mappingPreview.replaceChildren();
    mappingError.hidden = true;
    mappingError.textContent = "";
    mappingText.removeAttribute("aria-invalid");
    const mapping = selectedMapping();
    const chosen = Object.values(mapping);
    const duplicate = new Set(chosen.filter(Boolean)).size !== chosen.filter(Boolean).length;
    mappingChoices.forEach(([meaning, , label]) => {
      mappingPreview.append(element("li", `${label} ← ${mapping[meaning] || "선택 안 됨"}`));
    });
    mappingConfirm.disabled = duplicate || chosen.some((key) => !key || !mappingKeys.includes(key));
    if (duplicate) mappingFailure("각 항목에는 서로 다른 원본 필드를 선택하세요.", false);
  }

  function discoverMappingFields() {
    if (isPending()) return;
    resetMappingChoices();
    const invalid = validateText("access", mappingText.value);
    if (invalid) return mappingFailure(`${invalid[1]} JSONL 입력을 확인한 뒤 필드 이름 확인을 다시 누르세요.`);
    const lines = mappingText.value.split("\n");
    if (lines.at(-1) === "") lines.pop();
    let common = null;
    try {
      for (const line of lines) {
        const row = JSON.parse(line);
        if (row === null || typeof row !== "object" || Array.isArray(row) ||
            Object.keys(row).some((key) => { const value = row[key]; return /[\p{Cc}\p{Cf}\p{Cs}]/u.test(key) ||
              (value !== null && typeof value === "object") ||
              (typeof value === "number" && !Number.isFinite(value)) ||
              (typeof value === "string" && /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)); })) throw new Error();
        // JSON.parse validates syntax first. Inspect string tokens only to
        // reject duplicate decoded keys in this deliberately flat object.
        const seen = new Set();
        for (const token of line.matchAll(/"(?:\\.|[^"\\])*"/g)) {
          if (!line.slice(token.index + token[0].length).trimStart().startsWith(":")) continue;
          const key = JSON.parse(token[0]);
          if (seen.has(key)) throw new Error();
          seen.add(key);
        }
        const keys = Object.keys(row).filter((key) => key.length > 0);
        common = common === null ? keys : common.filter((key) => keys.includes(key));
      }
    } catch {
      return mappingFailure("각 줄에 중복 키 없는 평평한 JSON 객체 하나가 필요합니다. 중첩 객체·배열·비유한 수·제어 문자를 확인하세요.");
    }
    if (!common || common.length < 5) return mappingFailure("모든 줄에 공통으로 있는 필드가 다섯 개 이상 필요합니다. 누락된 줄과 필드 이름을 확인하세요.");
    mappingKeys = common;
    mappingChoices.forEach(([, id]) => {
      const select = document.getElementById(id);
      for (const key of common) {
        const option = element("option", key);
        option.value = key;
        select.append(option);
      }
    });
    mappingFields.disabled = false;
    mappingStatus.textContent = `${lines.length}줄의 공통 필드 ${common.length}개를 확인했습니다. 값은 표시하지 않습니다. 아래 다섯 항목을 직접 선택하세요.`;
    document.getElementById(mappingChoices[0][1]).focus();
  }

  mappingText.addEventListener("input", resetMappingChoices);
  mappingDiscover.addEventListener("click", discoverMappingFields);
  mappingClear.addEventListener("click", () => { if (!isPending()) { clearMappingInput(); mappingText.focus(); } });
  mappingChoices.forEach(([, id]) => document.getElementById(id).addEventListener("change", mappingSelectionChanged));
  function prepareRequest() {
    const mapping = selectedMapping();
    if (mappingKeys.length === 0 || Object.values(mapping).some((key) => !key || !mappingKeys.includes(key)) ||
        new Set(Object.values(mapping)).size !== 5 || !mappingConfirm.checked) {
      mappingFailure("필드 이름 확인 후 다섯 항목을 서로 다르게 선택하고 연결 확인에 체크하세요.");
      return null;
    }
    const body = {schema_version: 1, confirmed: true, mapping, log_text: mappingText.value};
    if (new TextEncoder().encode(JSON.stringify(body)).byteLength > 96 * 1024) {
      mappingFailure("요청 크기가 96 KiB를 넘었습니다. 입력 범위를 줄이세요.");
      return null;
    }
    return body;
  }
  return {inputModeMapping, mappingPanel, mappingText, mappingDiscover, mappingClear, mappingFields,
    mappingConfirm, mappingResultNotice, clearMappingInput, selectedMapping, mappingFailure,
    prepareRequest,
    get keys() { return mappingKeys; }};
  }
  window.jsonAccessMapping = Object.freeze({create});
})();
