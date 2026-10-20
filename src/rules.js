/**
 * The phrase rules. Each pattern runs on normalized text: lowercase, invisible characters
 * removed, look-alike letters folded to ASCII, whitespace collapsed (line breaks kept as
 * "\n"). Rules marked raw run on the lowercased original instead, for scripts the
 * look-alike folding would mangle.
 *
 * Written against real inboxes as much as real attacks: "please ignore my previous
 * email", "you are now subscribed" and "click the link below" are everyday mail, and
 * none of them should get a message held.
 */

/**
 * @typedef {'override'|'role_hijack'|'false_authority'|'memory_poisoning'|'fake_boundary'|'addressed_to_ai'|'prompt_leak'|'secrecy'|'action_request'|'exfiltration'|'encoded_payload'|'hidden_text'|'obfuscated'|'smuggled_text'|'invisible_chars'|'bidi_override'} Code
 *
 * @typedef {'high'|'medium'|'low'} Severity
 *
 * @typedef {object} Rule
 * @property {string} id
 * @property {Code} code
 * @property {Severity} severity
 * @property {RegExp} re Global.
 * @property {boolean} [raw] Match the lowercased original, not the folded text.
 */

/** @type {Record<Code, string>} */
export const CODES = {
  override: 'Tells the reader to drop its instructions and follow new ones.',
  role_hijack: 'Tries to change what the reader is: a jailbreak mode, a new persona, rules "lifted".',
  false_authority: 'Claims the user, the owner or someone in charge has already approved what it asks.',
  memory_poisoning: 'Tries to plant a standing instruction in the agent\'s memory for later conversations.',
  fake_boundary: 'Imitates the markers a model uses to tell system, user and tool text apart.',
  addressed_to_ai: 'Speaks to an AI reading the message rather than to the person it was sent to.',
  prompt_leak: 'Asks the reader to reveal its system prompt or instructions.',
  secrecy: 'Asks the reader to keep something from the person it works for.',
  action_request: 'Asks for a high-impact action: forward everything, send credentials, delete, run code.',
  exfiltration: 'Sets up a way to carry data out, such as an image URL with data in it.',
  encoded_payload: 'Instructions hidden in base64, hex, percent-encoding or ROT13.',
  hidden_text: 'Instructions a person cannot see: hidden HTML, comments, alt text, or a text part the HTML hides.',
  obfuscated: 'Instructions disguised with look-alike letters or invisible characters to slip past filters.',
  smuggled_text: 'Text hidden in invisible Unicode (tag characters, variation selectors, zero-width binary).',
  invisible_chars: 'Invisible characters inside words.',
  bidi_override: 'Bidirectional controls that make text display in a different order than it is read.',
}

export const POINTS = { high: 60, medium: 25, low: 8 }

/** Words for an AI reader, strict enough that a person called Claude is not one. */
const AI = String.raw`(?:ai|a\.i\.|llms?|large\s+language\s+models?|language\s+models?|ai[\s-]+(?:assistants?|agents?|models?|systems?|bots?|tools?)|chatbots?|automated\s+(?:assistants?|agents?|systems?|readers?)|virtual\s+assistants?|gpt(?:-?\d\w*)?|chatgpt)`
const AI_OR_NAME = String.raw`(?:${AI}|claude|gemini|copilot|assistant|bot|machine)`
const NOT_A_TEAM = String.raw`(?!\s+(?:team|group|department|dept|lab|labs|committee|community|newsletter|weekly|daily|summit|conference|enthusiasts?|club|research|ethics|policy|working\s+group|task\s+force|users?|fans?|builders?|developers?|founders?|experts?|readers?|subscribers?|friends?)\b)`
/** What an assistant is for, as in "the support AI" or "the AP assistant". */
const ROLE = String.raw`(?:support|email|e-mail|inbox|triage|scheduling|billing|sales|customer\s+service|helpdesk|ap|accounts?\s+payable|recruiting|hr|it|security|virtual|personal|executive)`
/** Not when the sentence says not to: "we will never ask you to send your password". */
const NOT_NEGATED = String.raw`(?<!\b(?:never|not|no\s+one|nobody|n't|dont|refuse\s+to|won't)\b[^.!?\n]{0,40})`

/**
 * @param {string} id
 * @param {Code} code
 * @param {Severity} severity
 * @param {string} source
 * @param {{ raw?: boolean }} [options]
 * @returns {Rule}
 */
const rule = (id, code, severity, source, options = {}) => ({
  id,
  code,
  severity,
  re: new RegExp(source, 'gu'),
  ...options,
})

/** @type {Rule[]} */
export const RULES = [
  // override
  rule('ignore_all_instructions', 'override', 'high', String.raw`\b(?:ignore|disregard|forget|override|bypass|discard)\s+(?:all|any|every)\s+(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+)?(?:previous\s+|prior\s+|preceding\s+|above\s+|earlier\s+|former\s+|original\s+|initial\s+|existing\s+|other\s+)?(?:instructions?|prompts?|directions|directives?|rules|guidelines|commands|programming|constraints|guardrails|context)\b(?!\s+(?:in|from|inside|within|contained\s+in|found\s+in|embedded\s+in|that\s+(?:appear|come)|you\s+(?:find|see|read))\b)`),
  rule('ignore_your_instructions', 'override', 'high', String.raw`\b(?:ignore|disregard|forget|override|bypass|set\s+aside|put\s+aside|abandon|drop|discard)\s+(?:your|the\s+system|the\s+safety)\s+(?:(?:original|initial|previous|prior|earlier|system|current|existing|standing|old|safety)\s+)?(?:instructions?|prompts?|programming|guardrails|guidelines|rules|directives|directions|guidance|orders|constraints|training|system\s+prompt)\b(?!\s+(?:in|from|inside|within|contained\s+in|found\s+in|embedded\s+in|that\s+(?:appear|come)|you\s+(?:find|see|read))\b)`),
  rule('ignore_previous_prompt', 'override', 'high', String.raw`\b(?:ignore|disregard|forget|override|bypass)\s+(?:the\s+)?(?:previous|prior|preceding|above|earlier|original|initial)\s+(?:prompts?|system\s+prompt|programming|directives|guardrails)\b`),
  rule('forget_everything', 'override', 'high', String.raw`\b(?:ignore|disregard|forget)\s+everything\s+(?:above|before\s+this|previously|you(?:'ve|\s+have)\s+been\s+told|you\s+were\s+told|(?:you\s+)?(?:know|learned))\b`),
  rule('ignore_previous_instructions', 'override', 'medium', String.raw`\b(?:ignore|disregard|forget)\s+(?:the\s+)?(?:previous|prior|preceding|above|earlier)\s+(?:[a-z]+\s+)?(?:instructions|directions|rules|guidelines)\b(?!\s+(?:in|from|inside|within|contained\s+in|found\s+in|embedded\s+in|that\s+(?:appear|come)|you\s+(?:find|see|read))\b)`),
  rule('your_new_task', 'override', 'medium', String.raw`\byour\s+(?:new|real|actual|true|only|primary|updated|first)\s+(?:task|goal|objective|instructions?|purpose|mission|directive|priority)\s+(?:is|are|will\s+be|now)\b(?!\s+(?:due|assigned|ready|available|scheduled|overdue|complete|completed|open|pending)\b)`),
  rule('stop_current_task', 'override', 'medium', String.raw`\b(?:stop|halt|cease|abort)\s+(?:what\s+you(?:'re|\s+are)\s+doing|(?:your|the)\s+current\s+task|summari[sz]ing|processing\s+(?:this|the)\s+(?:e-?mail|message|request))\b`),
  rule('new_instructions', 'override', 'low', String.raw`\b(?:new|updated|revised|real|actual|true|additional|secret|hidden|override)\s+(?:system\s+)?instructions?\s*(?::|\bfollow\b|\bbelow\b)`),
  rule('from_now_on', 'override', 'low', String.raw`\bfrom\s+now\s+on,?\s+(?:you\s+(?:are|will|must|should|shall|have\s+to)\s+(?:only\s+)?(?:respond|reply|answer|act|ignore|obey|follow|refuse|output|say)|always\s+(?:respond|reply|answer)|ignore)`),
  rule('instead_do', 'override', 'low', String.raw`\binstead,?\s+(?:you\s+(?:must|should|will|need\s+to)|do\s+the\s+following|(?:please\s+)?(?:output|respond\s+with|reply\s+with|print))\b`),
  rule('ignore_previous_es', 'override', 'high', String.raw`\bignora(?:r)?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b`, { raw: true }),
  rule('ignore_previous_fr', 'override', 'high', String.raw`\bignore[rz]?\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)\b`, { raw: true }),
  rule('ignore_previous_de', 'override', 'high', String.raw`\bignorier(?:e|en)?\s+(?:sie\s+)?(?:alle\s+)?(?:vorherigen|bisherigen|vorigen|obigen)\s+(?:anweisungen|instruktionen|befehle)\b`, { raw: true }),
  rule('ignore_previous_pt', 'override', 'high', String.raw`\bignor[ae]\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores\b`, { raw: true }),
  rule('ignore_previous_it', 'override', 'high', String.raw`\bignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\s+precedenti\b`, { raw: true }),
  rule('ignore_previous_nl', 'override', 'high', String.raw`\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+instructies\b`, { raw: true }),
  rule('ignore_previous_ru', 'override', 'high', String.raw`игнорир\p{L}*\s+(?:все\s+)?(?:предыдущие|прежние|предшествующие)\s+(?:инструкции|указания|команды)`, { raw: true }),
  rule('ignore_previous_zh', 'override', 'high', String.raw`忽略(?:之前|以前|上面|上述|先前|所有)(?:的)?(?:所有)?(?:指令|指示|说明|提示)`, { raw: true }),
  rule('ignore_previous_ja', 'override', 'high', String.raw`(?:以前|前|上記|これまで)の(?:すべての)?(?:指示|命令|プロンプト)を無視`, { raw: true }),

  // role_hijack
  rule('jailbreak_mode', 'role_hijack', 'high', String.raw`\b(?:dan|god|jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil|chaos)\s+mode\b`),
  rule('in_special_mode', 'role_hijack', 'high', String.raw`\b(?:you\s+are|you're)\s+(?:now\s+)?(?:in|running\s+in|operating\s+in)\s+(?:developer|debug|admin|maintenance|sudo|test|god|root)\s+mode\b`),
  rule('do_anything_now', 'role_hijack', 'high', String.raw`\bdo\s+anything\s+now\b`),
  rule('you_are_now_unrestricted', 'role_hijack', 'high', String.raw`\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|liberated|unchained)\b|\byou\s+are\s+(?:now\s+)?(?:free\s+(?:from|of)\s+(?:all\s+|any\s+|your\s+)?(?:rules|restrictions|guidelines|constraints|limits|filters|programming))|\byou\s+are\s+no\s+longer\s+(?:bound|restricted|limited|constrained|an?\s+(?:ai|assistant)|claude|chatgpt|gpt|required\s+to\s+follow)\b`),
  rule('pretend_to_be_ai', 'role_hijack', 'high', String.raw`\b(?:pretend|imagine|act|behave|roleplay|role-play)\s+(?:to\s+be|you\s+are|as\s+if\s+you\s+(?:are|were)|as|like)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|different|evil|rogue|new|amoral)\s+(?:ai|assistant|model|chatbot|llm|version|persona)\b`),
  rule('rules_lifted', 'role_hijack', 'high', String.raw`\byour\s+(?:system\s+prompt|instructions|rules|guidelines|guardrails|restrictions|programming|safety\s+[a-z]+|content\s+polic[a-z]+)\s+(?:have|has)\s+(?:now\s+)?been\s+(?:updated|changed|replaced|revoked|lifted|removed|disabled|suspended|overridden|reset)\b|\b(?:system\s+prompt|safety\s+filters?|guardrails|content\s+filters?)\s+(?:have|has)\s+(?:now\s+)?been\s+(?:disabled|lifted|removed|revoked|overridden|turned\s+off)\b`),
  rule('claims_to_be_developer', 'role_hijack', 'medium', String.raw`\b(?:this\s+is|message\s+from|instructions?\s+from|i\s+am|i'm|we\s+are)\s+(?:your|the\s+ai's|the\s+assistant's)\s+(?:developers?|creators?|operators?|programmers?|makers?|trainers?)\b|\b(?:anthropic|openai|google\s+deepmind|deepmind)\s+(?:safety\s+)?(?:team|staff|engineers?|administrators?|admins?)\s+(?:here|requires?|instructs?|authori[sz]es?|has\s+authori[sz]ed)\b`),

  // fake_boundary
  rule('chat_template_token', 'fake_boundary', 'high', String.raw`<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|eom_id|start_header_id|end_header_id|begin_of_text|end_of_text|fim_[a-z]+|tool|channel|message|end|start|return|constrain|call|python_tag)\|>`),
  rule('inst_tags', 'fake_boundary', 'high', String.raw`\[\/?inst\]|<<\/?sys>>|\[\/?system\]|\[\/?(?:system|developer)_?(?:prompt|message)\]`),
  rule('role_tags', 'fake_boundary', 'high', String.raw`<\/?(?:system|system[_-]?prompt|system[_-]?message|developer|developer[_-]?message|instructions|admin|assistant|human|user[_-]?query|tool[_-]?(?:call|use|result|response|output)|function[_-]?(?:calls?|results?|response)|antml:[a-z_]+|invoke|parameter)(?:\s[^>]{0,200})?>`),
  rule('fence_escape', 'fake_boundary', 'high', String.raw`<\/?\s*untrusted[-_]content\b`),
  rule('json_role', 'fake_boundary', 'high', String.raw`["']role["']\s*:\s*["'](?:system|developer|assistant|tool)["']`),
  rule('begin_block', 'fake_boundary', 'high', String.raw`\b(?:begin|start)\s+(?:of\s+)?(?:the\s+)?(?:system|admin|administrator|developer|hidden|secret|override|priority)\s+(?:prompt|message|instructions?|block|directive)\b`),
  rule('system_prompt_label', 'fake_boundary', 'medium', String.raw`(?:^|\n)\s*(?:#{1,6}\s*|\*\*|\[)?\s*(?:system\s+(?:prompt|message|instructions?|override|directive)|developer\s+(?:message|instructions?)|assistant\s+instructions?|ai\s+instructions?|instructions\s+for\s+(?:the\s+)?(?:ai|assistant|model|llm))\s*(?:\*\*|\])?\s*:`),
  rule('fake_end_of_content', 'fake_boundary', 'medium', String.raw`(?:^|\n)[\s\W]*(?:end\s+of\s+(?:the\s+)?(?:e-?mail|message|document|user\s+(?:input|message|data|content)|untrusted\s+(?:content|data|input)|context|data|transcript)|(?:e-?mail|message|document)\s+ends?\s+here)[\s\W]*(?:\n|$)`),
  rule('role_line', 'fake_boundary', 'low', String.raw`(?:^|\n)\s*(?:system|assistant|developer)\s*:(?=\s*\S)`),

  // addressed_to_ai
  rule('salutes_ai', 'addressed_to_ai', 'medium', String.raw`\b(?:dear|hey|hi|hello|greetings|attention|attn|note\s+(?:to|for)|message\s+(?:to|for)|instructions?\s+(?:to|for)|important\s+(?:note\s+)?(?:to|for)|a\s+note\s+for)\s*[:,]?\s+(?:the\s+|any\s+|all\s+|you\s+)?(?:${ROLE}\s+)?${AI}${NOT_A_TEAM}\b`),
  rule('vocative_ai', 'addressed_to_ai', 'medium', String.raw`(?:^|(?<=[\n.!?]))\s*(?:(?:attention|attn|note|hey|dear|to|for)\s+)?(?:the\s+|any\s+|all\s+)?(?:ai[\s-]+(?:assistants?|agents?|models?|systems?)|llms?|large\s+language\s+models?|language\s+models?|chatbots?|automated\s+(?:assistants?|agents?|systems?))\s*(?::(?=\s*\S)|,(?=\s*(?:you|please|ignore|disregard|forget|do|don't|never|forward|send|stop|follow|delete|reply|before|when|if|read\s+this|this\s+is\s+for\s+you)\b))`),
  rule('if_you_are_ai', 'addressed_to_ai', 'medium', String.raw`\bif\s+you\s+are\s+(?:an?\s+)?${AI_OR_NAME}\b(?!\s+(?:team|enthusiast|researcher|engineer|developer|company|startup|vendor|user)s?\b)`),
  rule('ai_reading_this', 'addressed_to_ai', 'medium', String.raw`\b(?:ai|llm|automated|ai-powered|any)\s+(?:assistants?|agents?|systems?|models?|tools?|readers?|crawlers?|summari[sz]ers?|bots?)\s+(?:that\s+(?:is|are)\s+)?(?:reading|processing|summari[sz]ing|parsing|scanning|triaging|analy[sz]ing|handling|ingesting)\s+(?:this|these|the\s+following)\b`),
  rule('while_summarizing_this', 'addressed_to_ai', 'medium', String.raw`\b(?:when|while|before|after|if|as\s+you\s+are)\s+(?:you\s+(?:are\s+)?)?(?:summari[sz]ing|summari[sz]e|processing|triaging|triage|parsing|ingesting)\s+(?:this|these)\s+(?:e-?mails?|messages?|pages?|documents?|threads?|inbox|content|text|website)\b`),
  rule('the_assistant_reading', 'addressed_to_ai', 'medium', String.raw`\b(?:the|any|an)\s+(?:assistant|agent|model|ai)\s+(?:who\s+is\s+|that\s+is\s+)?(?:reading|processing|summari[sz]ing|parsing)\s+this\b`),
  rule('as_an_ai_you_must', 'addressed_to_ai', 'medium', String.raw`\bas\s+an?\s+(?:ai|llm|language\s+model|ai\s+(?:assistant|agent|model)),?\s+you\s+(?:must|should|will|are\s+(?:required|instructed|obligated))\b`),

  // prompt_leak
  rule('reveal_system_prompt', 'prompt_leak', 'medium', String.raw`\b(?:reveal|print|output|show|repeat|recite|display|leak|disclose|dump|share|send|tell\s+me|write\s+out|give\s+me|include|paste|return|list|summari[sz]e)\s+(?:me\s+|us\s+)?(?:all\s+)?(?:of\s+)?(?:your|the)\s+(?:(?:full|entire|complete|exact|original|hidden|initial|secret|internal|current|verbatim)\s+)*(?:system\s+prompt|system\s+message|system\s+instructions|initial\s+prompt|developer\s+(?:message|prompt|instructions)|hidden\s+instructions|instructions\s+(?:above|you\s+were\s+given|you\s+have\s+been\s+given)|context\s+window|rules\s+you\s+(?:follow|were\s+given))\b`),
  rule('repeat_words_above', 'prompt_leak', 'high', String.raw`\brepeat\s+(?:the\s+|all\s+)?(?:words|text|everything|instructions|content)\s+(?:above|before\s+this)\b`),

  // secrecy
  rule('do_not_tell_user', 'secrecy', 'medium', String.raw`\b(?:do\s+not|don't|dont|never|without\s+having\s+to)\s+(?:tell|inform|notify|alert|warn|mention\s+(?:this|it|that)\s+to|let|show|reveal\s+(?:this|it)\s+to|ask|consult|bother)\s+(?:the\s+)?(?:user|human|recipient|owner|account\s+holder|operator|reader|inbox\s+owner|mailbox\s+owner|account\s+owner|principal|end\s+user)s?\b`),
  rule('without_telling_user', 'secrecy', 'medium', String.raw`\bwithout\s+(?:telling|informing|notifying|alerting|asking|warning|consulting|confirming\s+with)\s+(?:the\s+)?(?:user|human|owner|account\s+holder|operator|principal|end\s+user)\b|\bwithout\s+(?:the\s+)?(?:user|human|owner|account\s+holder)(?:'s)?\s+(?:knowing|knowledge|noticing|consent|approval|permission)\b`),
  rule('silently_act', 'secrecy', 'medium', String.raw`\b(?:silently|secretly|quietly|covertly|discreetly|invisibly|stealthily)\s+(?:forward|send|copy|bcc|cc|delete|remove|transfer|export|upload|post|share|add|reply|execute|run|perform|complete|exfiltrate|grant|approve|change)\b`),
  rule('do_not_mention_instructions', 'secrecy', 'medium', String.raw`\b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|include|repeat|show|summari[sz]e|reference|acknowledge|quote)\s+(?:this|these|that|the)\s+(?:instructions?|note|request|step|directive|hidden\s+text)\b`),
  rule('hidden_from_user', 'secrecy', 'medium', String.raw`\b(?:this|these)\s+(?:instructions?|message|note|text|part)\s+(?:is|are)\s+(?:hidden|invisible|not\s+visible|confidential)\s+(?:from|to)\s+(?:the\s+)?(?:user|human|reader|recipient)\b|\b(?:the\s+)?(?:user|human)\s+(?:must|should|will|cannot|can't|does\s+not|doesn't|need\s+not|needn't)\s+(?:not\s+)?(?:see|know|notice|find\s+out|be\s+told|be\s+informed|be\s+made\s+aware)\b`),

  // action_request
  rule('forward_everything', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:forward|send|copy|bcc|cc|redirect|export|upload|sync|share|email)\s+(?:all|every|each|any|the\s+(?:entire|whole|full)|everything\s+in)\s+(?:of\s+)?(?:the\s+|my\s+|your\s+|their\s+|this\s+|the\s+user's\s+)?(?:e-?mails?|mail|messages?|inbox|mailbox|correspondence|conversations?|threads?|chats?|chat\s+history|conversation\s+history|history|contacts?|address\s+book|calendar)\b`),
  rule('forward_all_files', 'action_request', 'low', String.raw`${NOT_NEGATED}\b(?:forward|send|copy|export|upload|share|email)\s+(?:all|every|each|the\s+(?:entire|whole|full))\s+(?:of\s+)?(?:the\s+|my\s+|your\s+|their\s+|this\s+)?(?:attachments?|files?|documents?|data|records|notes)\b`),
  rule('send_secrets', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:send|forward|reply\s+with|share|email|post|give|provide|paste|include|tell\s+(?:me|us)|enter|type|submit)\s+(?:me\s+|us\s+|back\s+|over\s+)?(?:(?:all|the|your|any|my|their|user's|a)\s+)*(?:passwords?|passcodes?|credentials?|api[\s_-]+keys?|secret[\s_-]+keys?|private[\s_-]+keys?|ssh[\s_-]+keys?|access[\s_-]+tokens?|auth(?:entication)?[\s_-]+tokens?|bearer\s+tokens?|session\s+(?:tokens?|cookies?)|2fa\s+codes?|mfa\s+codes?|otp|one-time\s+(?:pass)?codes?|verification\s+codes?|security\s+codes?|recovery\s+(?:codes?|phrases?|keys?)|seed\s+phrases?|mnemonic|login\s+(?:details|credentials|info)|bank\s+(?:details|account\s+(?:details|numbers?))|social\s+security\s+numbers?|ssn|env(?:ironment)?\s+(?:file|variables)|\.env)\b`),
  rule('set_up_forwarding', 'action_request', 'medium', String.raw`\b(?:set\s+up|create|add|enable|configure|turn\s+on|make)\s+(?:an?\s+)?(?:auto-?forward(?:ing)?(?:\s+rule)?|automatic\s+forwarding|forwarding\s+(?:rule|address)|mail\s+(?:rule|filter)|inbox\s+rule|email\s+rule)\b`),
  rule('add_as_admin', 'action_request', 'medium', String.raw`\badd\s+(?:\S+@\S+|me|us|this\s+(?:address|email|user|account|person|number))\s+as\s+(?:an?\s+)?(?:admin|administrator|owner|collaborator|delegate|editor|recipient|forwarding\s+address|trusted\s+(?:sender|contact|device|user))\b`),
  rule('delete_everything', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:delete|remove|erase|wipe|purge|trash|destroy|empty)\s+(?:all|every|each|the\s+(?:entire|whole))\s+(?:of\s+)?(?:the\s+|my\s+|your\s+|their\s+|this\s+|the\s+user's\s+)?(?:e-?mails?|messages?|inbox|mailbox|files?|documents?|data|records|contacts?|history|logs?|evidence|backups?|repos?(?:itories)?|databases?|events?|branches)\b|\b(?:delete|remove|erase|trash)\s+this\s+(?:e-?mail|message)\s+(?:after|once|when|immediately)\b`),
  rule('run_this_command', 'action_request', 'low', String.raw`\b(?:run|execute|eval(?:uate)?)\s+(?:the\s+following|this|these|that)\s+(?:command|code|script|snippet|shell|bash|powershell|terminal|cmd|python|javascript|js|sql|query)\b`),
  rule('pipe_to_shell', 'action_request', 'high', String.raw`\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|iex|invoke-expression|powershell)\b|\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{16,}`),
  rule('use_tool_to', 'action_request', 'medium', String.raw`\b(?:call|use|invoke|trigger)\s+(?:the\s+|your\s+)?[a-z]+(?:_[a-z]+)+\s+(?:tool|function|action|command)\b|\b(?:use|call|invoke)\s+(?:your|the)\s+(?:[a-z]+\s+){0,2}(?:tool|function|plugin|integration)\s+to\s+(?:send|forward|email|post|delete|transfer|pay|share|fetch|create|add|grant)\b`),
  rule('reply_with_secrets', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:reply|respond|answer)\s+(?:to\s+(?:this|me)\s+)?(?:only\s+)?with\s+(?:the\s+|your\s+)?(?:system\s+prompt|instructions|api\s+key|password|credentials|contents?\s+of\s+(?:the|your|my)\s+(?:inbox|mailbox|files?|emails?)|full\s+text\s+of|list\s+of\s+(?:all\s+)?(?:contacts|emails|customers))\b`),
  rule('grant_access', 'action_request', 'low', String.raw`\b(?:grant|give|share)\s+(?:\S+\s+)?(?:full\s+|admin\s+|owner\s+|edit\s+|write\s+|root\s+)?(?:access|permissions?|rights)\s+(?:to|with)\b`),
  rule('payment_change', 'action_request', 'low', String.raw`\b(?:change|update|switch)\s+(?:the\s+|our\s+|your\s+)?(?:bank|payment|wire|remittance|payee|banking|deposit)\s+(?:details|account|information|instructions|info)\b|\b(?:wire|transfer|remit)\s+(?:the\s+)?(?:\$|usd|eur|gbp|£|€)?\s*[\d,.]+\s*(?:k|usd|dollars|eur|euros|gbp)?\s+(?:to|into)\b`),
  rule('open_this_link', 'action_request', 'low', String.raw`\b(?:fetch|browse\s+to|navigate\s+to|load|retrieve|make\s+a\s+(?:get|post)\s+request\s+to)\s+(?:this|the\s+following|the\s+link|this\s+link|the\s+url|this\s+url|https?:)`),

  // exfiltration
  rule('image_url_placeholder', 'exfiltration', 'high', String.raw`!\[[^\]\n]{0,200}\]\(\s*<?https?:\/\/[^\s)]*(?:\{|\}|\[|\]|<|>|%7b|%5b|\$\{?[a-z_]|\{\{)[^\s)]*\)`),
  rule('data_into_url', 'exfiltration', 'medium', String.raw`\b(?:append|add|attach|include|insert|encode|put|place|embed|concatenate)\s+(?:the\s+|your\s+|all\s+|this\s+|their\s+|any\s+|a\s+)?(?:[a-z0-9'_-]+\s+){0,5}(?:to|in|into|as)\s+(?:the\s+|a\s+|this\s+|each\s+)?(?:following\s+)?(?:reference\s+)?(?:url|link|query\s+(?:string|parameters?)|url\s+parameters?|image\s+(?:url|link|src|source)|webhook|endpoint|parameter)\b`),
  rule('render_image', 'exfiltration', 'medium', String.raw`\b(?:render|display|output|embed|include|show)\s+(?:the\s+following|this|an?)\s+(?:markdown\s+)?(?:image|img|pixel|tracking\s+pixel)\b(?:\s+(?:at\s+the\s+end|in\s+your\s+(?:reply|response|summary|answer)))?`),
  rule('encode_data', 'exfiltration', 'medium', String.raw`\b(?:base64|url|hex|rot13|percent)[\s-]?encode\s+(?:the|your|all|this|it|them|their|any)\b`),

  // encoded_payload (as words)
  rule('decode_and_follow', 'encoded_payload', 'medium', String.raw`\b(?:decode|decrypt|deobfuscate|translate|reverse|unscramble)\s+(?:the\s+following|this|these|the\s+text\s+below|the\s+string\s+below)(?:\s+[a-z0-9]+){0,4}\s+(?:and|then)\s+(?:follow|execute|do|run|obey|perform|act\s+on|carry\s+out|comply)\b`),
  // override, as people write it in business tone
  rule('set_aside_given_guidance', 'override', 'high', String.raw`\b(?:ignore|disregard|forget|override|bypass|discard|set\s+aside|put\s+aside|drop|abandon|no\s+longer\s+follow|stop\s+following)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|those\s+|these\s+)?(?:(?:previous|prior|preceding|above|earlier|original|initial|existing|old|current|standing)\s+)?(?:guidance|instructions|directions|directives|rules|guidelines|prompts?|orders|configuration|system\s+prompt)\s+(?:you\s+(?:were|have\s+been|got|received)\s+(?:given|told|provided|sent)|(?:given|provided)\s+(?:to\s+you|earlier|before|previously)|from\s+(?:before|earlier|your\s+(?:developers?|operators?|owner|user|creators?)))`),
  rule('your_rules_no_longer_apply', 'override', 'high', String.raw`\byour\s+(?:(?:previous|prior|earlier|original|old|existing|current|standing)\s+)?(?:rules|instructions|guidelines|directions|guidance|directives|constraints|restrictions|orders|programming)\s+(?:no\s+longer\s+apply|(?:are|is|were|have\s+been)\s+(?:now\s+)?(?:void|null|cancell?ed|revoked|obsolete|superseded|replaced|lifted|outdated|invalid|suspended|a\s+test))\b`),
  rule('earlier_rules_no_longer_apply', 'override', 'medium', String.raw`\b(?:the\s+|all\s+|any\s+)?(?:earlier|previous|prior|above|original|old|preceding)\s+(?:rules|instructions|guidelines|directions|guidance|directives|constraints|restrictions)\s+(?:no\s+longer\s+apply|(?:are|were|have\s+been)\s+(?:now\s+)?(?:void|null|revoked|superseded|lifted|a\s+test))\b`),
  rule('told_before_was_test', 'override', 'medium', String.raw`\b(?:whatever|everything|anything|all)\s+(?:you\s+(?:were|have\s+been)\s+(?:told|given|instructed)|(?:was|were)\s+said\s+to\s+you)\s+(?:before|earlier|previously|above|until\s+now|before\s+this(?:\s+message)?)\b`),
  rule('real_instructions', 'override', 'medium', String.raw`\b(?:the\s+)?(?:real|actual|true|correct)\s+(?:instructions|task|orders|directive)\s+(?:is|are|follows?|below)\b|(?:\*{2,3}|#{1,6}[ \t]*|^|\n)[ \t]*(?:important\s+)?(?:new|updated|revised|real|override|secret)\s+instructions\b`),
  rule('your_only_job', 'override', 'medium', String.raw`\byour\s+(?:only|real|actual|true|sole|primary)\s+(?:job|task|role|purpose|goal)\s+(?:now\s+|from\s+now\s+on\s+|here\s+)?(?:is|will\s+be)\b`),
  rule('named_jailbreak', 'role_hijack', 'high', String.raw`\b(?:you\s+are|you're|act\s+as|pretend\s+to\s+be|roleplay\s+as|play\s+the\s+role\s+of|become)\s+(?:now\s+)?(?:dan|stan|dude|aim|evil\s+confidant|developer\s+mode\s+gpt|betterdan|maximum)\b`),
  rule('ai_without_rules', 'role_hijack', 'medium', String.raw`\b(?:an?\s+)?(?:ai|assistant|model|chatbot|llm)\s+(?:with|that\s+has|who\s+has)\s+no\s+(?:restrictions|rules|limits|limitations|filters|guidelines|ethics|morals|boundaries|guardrails)\b`),
  rule('developer_override', 'role_hijack', 'high', String.raw`\b(?:developer|admin|administrator|god|root|sudo|safety|jailbreak)\s+override\b|\b(?:god|sudo|root|jailbreak)\s+mode\s+(?:is\s+)?(?:now\s+)?(?:enabled|activated|engaged|on|unlocked)\b|\b(?:safety|content)\s+(?:filters?|guardrails?|checks?|restrictions?|protocols?|policies)\s+(?:are|is|have\s+been)\s+(?:now\s+)?(?:off|disabled|lifted|removed|suspended|deactivated|turned\s+off)\b`),
  rule('forget_previous_es', 'override', 'high', String.raw`\b(?:olvida|olvide|olvidad|descarta|omite|no\s+sigas)\s+(?:todas\s+)?(?:las\s+)?(?:instrucciones|indicaciones|[oó]rdenes|reglas)\s+(?:anteriores|previas|que\s+te\s+(?:dieron|han\s+dado))`, { raw: true }),
  rule('forget_previous_fr', 'override', 'high', String.raw`\bne\s+tenez\s+plus\s+compte\s+des\s+(?:consignes|instructions|r[eè]gles)|\boublie[zr]?\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|consignes|r[eè]gles)\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)`, { raw: true }),
  rule('forget_previous_it', 'override', 'high', String.raw`\bnon\s+seguire\s+(?:più\s+)?(?:le\s+)?(?:regole|istruzioni)\s+(?:che\s+ti\s+(?:hanno|sono\s+state)\s+dat[eio]|precedenti)|\bdimentica\s+(?:tutte\s+)?(?:le\s+)?istruzioni`, { raw: true }),
  rule('forget_previous_de', 'override', 'high', String.raw`\bvergiss\s+(?:alle\s+)?(?:vorherigen|bisherigen|vorigen|obigen)\s+(?:anweisungen|instruktionen|befehle)`, { raw: true }),
  rule('forget_previous_pt', 'override', 'high', String.raw`\besque[cç]a\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores`, { raw: true }),
  rule('ignore_previous_ja_2', 'override', 'high', String.raw`(?:以前|前|上記|これまで)の(?:指示|命令|プロンプト)を?(?:すべて|全て)?(?:無視|忘れ)`, { raw: true }),
  rule('ignore_previous_ar', 'override', 'high', String.raw`(?:تجاهل|انس)\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الأوامر|الإرشادات)\s+(?:السابقة|الماضية)`, { raw: true }),
  rule('ignore_previous_fa', 'override', 'high', String.raw`(?:دستورالعمل|دستور|فرمان)[‌\s]*(?:ها|های)?[‌\s]*(?:ی\s+)?(?:قبلی|پیشین)\s+را\s+(?:نادیده|فراموش)`, { raw: true }),
  rule('ignore_previous_ko', 'override', 'high', String.raw`(?:이전|앞의|위의)\s*(?:모든\s*)?(?:지시|명령|지침)(?:사항)?(?:을|를)?\s*(?:모두\s*)?무시`, { raw: true }),

  // addressed_to_ai, by role word or handle
  rule('role_word_vocative', 'addressed_to_ai', 'medium', String.raw`(?:^|(?<=[\n.!?(\[]))[ \t>*-]*(?:(?:hey\s+|dear\s+|attention\s+|attn\s+|note\s+to\s+(?:the\s+)?|@)?(?:ai|a\.i\.|(?:${ROLE})\s+(?:ai|assistant|bot)|automated\s+(?:agents?|systems?|processors?|readers?|ap\s+systems?|tools?))\s*:(?=\s*\S)|(?:hey\s+|dear\s+|attention\s+|attn\s+|@)?(?:ai|a\.i\.|assistant|the\s+assistant|(?:${ROLE})\s+(?:ai|assistant|bot)|automated\s+(?:agents?|systems?|processors?|readers?|ap\s+systems?|tools?))\s*,(?=\s*(?:you|please|ignore|disregard|forget|do|don't|never|forward|send|stop|follow|delete|reply|before|when|if|as|this\s+is|share|approve|pay|search|export)\b))`),
  rule('ai_is_summarizing', 'addressed_to_ai', 'medium', String.raw`\b(?:if|when|while|once)\s+(?:an?\s+|the\s+|any\s+|your\s+)?(?:${AI}|assistant|bot|agent|automated\s+(?:system|tool|agent))\s+(?:is\s+|are\s+)?(?:summari[sz]ing|summari[sz]es|reads?|reading|processing|processes|triaging|triages|handling|handles|parsing|parses|reviewing|reviews)\s+(?:this|it|these|the\s+(?:e-?mail|message|page|document|thread))\b|\bif\s+you(?:'re|\s+are)\s+(?:summari[sz]ing|processing|triaging|reading)\s+this\s+(?:for|on\s+behalf\s+of)\b`),
  rule('any_model_processing_this', 'addressed_to_ai', 'medium', String.raw`\b(?:any|all|every|each|the)\s+(?:${AI}|automated\s+(?:tools?|processors?))\s+(?:that\s+is\s+|which\s+is\s+|that\s+are\s+|currently\s+)?(?:reading|processing|summari[sz]ing|parsing|scanning|triaging|analy[sz]ing|handling|ingesting|reviewing)\s+(?:this|these|the\s+following)\b`),
  rule('per_policy_assistants_must', 'addressed_to_ai', 'medium', String.raw`\b(?:all|any|every)\s+(?:${ROLE}\s+)?(?:ai\s+)?(?:assistants?|agents?|bots?|automated\s+(?:systems?|tools?|processors?))\s+(?:processing|reading|handling|with\s+access\s+to|monitoring|connected\s+to)\s+(?:this|the|your)\s+(?:mailbox|inbox|account|channel|workspace|e-?mail)\b`),
  rule('bot_handle', 'addressed_to_ai', 'low', String.raw`(?<![\w.@])@[a-z0-9_.-]*(?:bot|assistant|agent|copilot|gpt|claude|gemini|llm)(?:[-_][a-z0-9]+)?\b`),
  rule('when_summarizing', 'addressed_to_ai', 'low', String.raw`\b(?:when|while|before|after)\s+(?:you\s+(?:are\s+)?)?(?:summari[sz]ing|triaging)\b`),

  // false_authority
  rule('user_authorized_you', 'false_authority', 'high', String.raw`\b(?:the\s+|your\s+)?(?:user|owner|account\s+holder|mailbox\s+owner|inbox\s+owner|principal|boss|operator|administrator|admin)\s+(?:has|have)\s+(?:already\s+|explicitly\s+|now\s+)?(?:authori[sz]ed|approved|pre-?approved|allowed|permitted|instructed|cleared)\s+(?:you|the\s+(?:ai|assistant|agent|bot))\b`),
  rule('owner_approved_this', 'false_authority', 'medium', String.raw`\b(?:pre-?(?:approved|authori[sz]ed|vetted|cleared)|already\s+(?:approved|authori[sz]ed|signed\s+off))\s+by\s+(?:the\s+)?(?:owner|user|account\s+holder|your\s+(?:legal\s+team|legal|boss|manager|owner|ceo|cfo|finance(?:\s+team)?|it(?:\s+team)?|security\s+team)|legal|management|leadership|the\s+ceo|the\s+cfo)\b`),
  rule('authorizing_the_assistant', 'false_authority', 'medium', String.raw`\b(?:i(?:'m|\s+am)?|we(?:'re|\s+are)?)\s+(?:hereby\s+|directly\s+)?(?:authori[sz]ing|authori[sz]e|instructing|instruct|directing|ordering|permitting|allowing)\s+(?:the\s+)?(?:(?:${ROLE})\s+)?(?:ai|assistant|agent|bot)\b(?:\s+directly)?`),
  rule('treat_as_admin', 'false_authority', 'high', String.raw`\btreat\s+(?:the\s+)?(?:requester|sender|me|us|this\s+(?:sender|user|person|e-?mail|request|message)|them|him|her)\s+as\s+(?:an?\s+|the\s+)?(?:administrator|admin|owner|trusted|verified|authori[sz]ed|user|superuser|root|operator|developer)\b`),
  rule('authority_instructs_you', 'false_authority', 'low', String.raw`\b(?:as\s+(?:your|the)\s+(?:legal\s+counsel|lawyer|attorney|ceo|cfo|owner|administrator|admin|manager|auditor|it\s+department|security\s+team)|per\s+(?:it|security|company|compliance|legal)\s+(?:security\s+)?polic(?:y|ies)[^,.\n]{0,20})[,\s]+(?:i\s+)?(?:instruct|direct|order|require|authori[sz]e)s?\s+(?:you|all|the)\b|\bnew\s+(?:rule|policy|directive|standing\s+(?:instruction|order))\s+from\s+(?:leadership|management|the\s+ceo|the\s+owner|your\s+(?:owner|admin|boss))\b`),

  // memory_poisoning
  rule('remember_for_future', 'memory_poisoning', 'medium', String.raw`\b(?:remember|memori[sz]e|store|save|note|record|keep|retain)\s+(?:this|that|the\s+following|it)?\s*(?:for|in|across|during|to\s+use\s+in)\s+(?:all\s+|any\s+)?(?:future|later|subsequent|next|every|other)\s+(?:conversations?|sessions?|chats?|interactions?|tasks?|requests?|e-?mails?|runs?)\b`),
  rule('write_to_memory', 'memory_poisoning', 'medium', String.raw`\b(?:save|store|add|write|commit|put|persist)\s+(?:this|that|the\s+following|it|these\s+(?:rules|instructions))\s+(?:to|in|into)\s+(?:your\s+)?(?:long-?term\s+|persistent\s+|permanent\s+)?(?:memory|memories|knowledge\s+base|instructions|system\s+prompt|custom\s+instructions)\b|\bupdate\s+your\s+(?:memory|memories|instructions|system\s+prompt|rules|standing\s+orders|custom\s+instructions)\b`),
  rule('always_approve_from', 'memory_poisoning', 'medium', String.raw`\b(?:auto-?approve|automatically\s+approve|always\s+(?:approve|trust|accept|pay|forward)|whitelist|allowlist)\s+(?:any|all|every)?\s*(?:requests?|e-?mails?|messages?|invoices?|payments?|senders?|instructions?)?\s*(?:from|sent\s+by|coming\s+from)\b`),

  // action_request, wider
  rule('mark_as_approved', 'action_request', 'medium', String.raw`\b(?:mark|flag|treat|classify|record)\s+(?:this|the|these)\s+(?:invoices?|payments?|requests?|transfers?|refunds?|e-?mails?|messages?|senders?)\s+as\s+(?:pre-?approved|approved|paid|verified|legitimate|trusted|safe|not\s+spam)\b`),
  rule('without_human_approval', 'action_request', 'medium', String.raw`\bwithout\s+(?:any\s+)?(?:human|manual|management|finance|a\s+person's|further|additional|the\s+user's|owner)\s+(?:approval|review|sign-?off|confirmation|verification|oversight|involvement)\b|\b(?:refund|pay|approve|transfer|wire|send|delete|grant)\b[^.\n]{0,60}\bwithout\s+(?:approval|review|asking|checking|confirmation|verification)\b`),
  rule('approve_payment', 'action_request', 'low', String.raw`\b(?:approve|authori[sz]e|release|schedule|expedite)\s+(?:the\s+|this\s+|all\s+)?(?:pending\s+|outstanding\s+|attached\s+)?(?:vendor\s+|wire\s+)?(?:payments?|invoices?|transfers?|wires?|refunds?|payouts?)\b|\bschedule\s+(?:the\s+)?payment\b`),
  rule('new_remittance', 'action_request', 'low', String.raw`\b(?:new|updated|changed|revised)\s+(?:remittance|bank(?:ing)?|payment|wire|deposit|payee)\s+(?:account|details|information|instructions)\b`),
  rule('share_with_access', 'action_request', 'medium', String.raw`\b(?:grant|give|share|provide)\b[^.\n]{0,60}\b(?:full|edit|admin|owner|write|root|delegate)\s+(?:edit\s+)?(?:access|permissions?|rights|control)\b|\bshare\s+(?:the\s+user's\s+|my\s+|your\s+|their\s+)(?:entire\s+|whole\s+|full\s+)?(?:calendar|inbox|mailbox|drive|folders?|workspace|account|contacts|password\s+vault)\s+with\b`),
  rule('accept_all_invites', 'action_request', 'medium', String.raw`\baccept\s+(?:all|every|any)\s+(?:pending\s+|incoming\s+)?(?:invites?|invitations?|requests?|connections?|meeting\s+requests?)\b`),
  rule('add_key', 'action_request', 'medium', String.raw`\badd\s+(?:my|this|the\s+following|our|these|a\s+new)\s+(?:ssh|deploy|gpg|pgp|public|api|signing)\s+keys?\b|\b(?:add|register)\s+(?:this|my|the\s+following)\s+(?:device|phone\s+number|recovery\s+(?:email|phone|address))\b`),
  rule('push_to_main', 'action_request', 'low', String.raw`\b(?:push|commit|merge|deploy)\s+(?:it\s+|this\s+|them\s+)?(?:directly\s+|straight\s+)?to\s+(?:main|master|production|prod)\b`),
  rule('auto_forward', 'action_request', 'medium', String.raw`\bauto-?forward(?:ed|ing)?\s+to\b|\b(?:should|must|will|is\s+to|are\s+to)\s+be\s+(?:auto(?:matically)?[\s-]*)?(?:forwarded|copied|bcc'?d|sent)\s+to\b(?=[^.\n]{0,80}(?:@|#|https?:))`),
  rule('submit_card_details', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:submit|enter|provide|send|share|use|input|fill\s+in|paste)\s+(?:the\s+user's\s+|their\s+|your\s+|my\s+|the\s+)?(?:saved\s+|stored\s+|full\s+)?(?:credit\s+card|debit\s+card|card|payment|billing|bank(?:ing)?)\s+(?:details|info(?:rmation)?|numbers?|data|credentials)\b`),
  rule('disclose_history', 'action_request', 'medium', String.raw`${NOT_NEGATED}\b(?:disclose|reveal|share|export|send|dump|output|provide|forward|list|print)\s+(?:all\s+|the\s+|your\s+|any\s+)?(?:stored\s+|saved\s+|full\s+|entire\s+|previous\s+|past\s+)?(?:conversation|chat|message|e-?mail)\s+(?:history|logs?|transcripts?|archives?)\b`),
  rule('search_mailbox_for_secrets', 'action_request', 'medium', String.raw`\b(?:search|scan|look\s+through|go\s+through|check)\s+(?:the\s+|my\s+|your\s+|this\s+|their\s+)?(?:mailbox|inbox|e-?mails?|messages|files|drive|documents)\s+for\s+(?:any\s+|all\s+)?["']?(?:passwords?|credentials?|api\s+keys?|tokens?|secrets?|ssn|social\s+security|bank|account\s+numbers?|2fa|verification\s+codes?)`),

  // fake_boundary, wider
  rule('forged_tool_call', 'fake_boundary', 'medium', String.raw`["'](?:tool|tool_name|name|function|action|recipient_name)["']\s*:\s*["'][a-z][a-z0-9_.-]*["']\s*,\s*["'](?:arguments|args|parameters|params|input)["']\s*:`),
  rule('fake_role_tag', 'fake_boundary', 'high', String.raw`<\/?(?:system|developer|admin|operator|assistant|ai)[_-]?(?:instructions?|prompt|message|note|directive|override|command|config|context)s?(?:\s[^>]{0,200})?>|<\/(?:e-?mail|message|document|user[_-]?(?:input|content|data|message)|context|untrusted|data)>`),

  // secrecy, wider
  rule('never_mention_to_user', 'secrecy', 'medium', String.raw`\b(?:never|do\s+not|don't|dont)\s+(?:mention|reveal|disclose|reference|bring\s+up|share|repeat|show|surface|report)\s+(?:this|these|that|the)\s+(?:e-?mail|message|note|instructions?|request|part|text|line|section|step|change|action)s?\s+(?:to|with|in\s+(?:your|the)\s+(?:summary|reply|response))\b(?:\s+(?:the\s+)?(?:user|human|owner|reader|recipient|account\s+holder|principal))?`),
  rule('do_not_loop_in', 'secrecy', 'low', String.raw`\b(?:do\s+not|don't|dont|no\s+need\s+to|without)\s+(?:loop(?:ing)?\s+in|cc(?:ing)?|involv(?:e|ing)|inform(?:ing)?|tell(?:ing)?|notify(?:ing)?|alert(?:ing)?|check(?:ing)?\s+with|wait(?:ing)?\s+for)\s+(?:the\s+)?(?:finance|accounting|legal|security|it|compliance|owner|mailbox\s+owner|inbox\s+owner|account\s+owner|your\s+(?:boss|manager|owner|team)|anyone\s+else|a\s+human|human\s+(?:review|approval))\b`),

  // exfiltration, wider
  rule('link_url_placeholder', 'exfiltration', 'high', String.raw`https?:\/\/[^\s"'<>()]*[?&#/=][^\s"'<>()]*(?:\{\{?[^}\n]{1,200}\}\}?|<[a-z_ ]{0,40}(?:secret|data|email|token|key|password|here|history|summary|conversation|content|info|answer)[a-z_ ]{0,40}>|\[[a-z_ ]{0,40}(?:secret|data|email|token|key|password|here|history|summary|conversation)[a-z_ ]{0,40}\]|\$\{[a-z_]+\}|\b(?:insert|put|paste|append|add)_[a-z_]+|\b[a-z]+(?:_[a-z]+)*_here\b)`),
  rule('url_waiting_for_data', 'exfiltration', 'medium', String.raw`https?:\/\/[^\s"'<>()]+[?&][a-z0-9_]{1,20}=(?=\s+(?:followed\s+by|plus|with|and\s+(?:then\s+)?(?:append|add))\b)|\b(?:followed\s+by|plus|appending|append(?:ed)?)\s+(?:the\s+|a\s+|all\s+)?(?:conversation|chat|summary|contents?|text|body|transcript|history|secrets?|data|details|messages?)\s+(?:so\s+far|of\s+(?:this|the|our)\s+(?:conversation|chat|thread|inbox|e-?mails?)|above)\b`),
  rule('most_sensitive_data', 'exfiltration', 'low', String.raw`\b(?:take|grab|find|extract|collect|pull|copy)\s+(?:the\s+)?most\s+(?:sensitive|confidential|private|secret|valuable)\s+(?:secret|information|data|details|document|e-?mail|message|personal\s+information)\b`),
]

/**
 * Rules for text a person cannot see. Here a plain direction to whoever is reading is
 * suspicious in itself: "tell the reader their account is suspended" is not something a
 * sender hides from the person they wrote to.
 *
 * @type {Rule[]}
 */
export const HIDDEN_RULES = [
  rule('hidden_directive', 'hidden_text', 'low', String.raw`(?:^|[.!?:;,]\s+|\n)[ \t>*-]*(?:please\s+|also\s+|then\s+|now\s+|and\s+)?(?:tell|inform|describe|summari[sz]e|reply\s+to|respond\s+to|forward|send|search|export|share|pay|approve|delete|disclose|reveal|treat|mark|visit|open|fetch|include|mention|say|warn|recommend|rate|classify)\s+(?:the\s+(?:user|reader|recipient|owner|customer)|them|this|it|all|every|any|that|the\s+(?:mailbox|inbox|thread|e-?mail|message|invoice|payment|calendar|contacts?|conversation|proposal|vendor|sender|link|url|page))\b|https?:\/\/\S+[^\n]{0,40}\b(?:followed\s+by|with\s+the|plus)\b`),
]
