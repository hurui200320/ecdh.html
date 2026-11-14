"use strict";
/* =====================================================================
 * ecdh.html v1 — DOM-free crypto core, shared by index.html (loaded as a
 * plain script before the UI code) and tests/crypto.test.js (required
 * directly under Node). No dependencies; everything is Web Crypto.
 *
 * Protocol: envelope bytes = 0x01 | ephPub[32] | iv[12] | AESGCM ct||tag
 *           text form      = TAG || codec(envelope bytes); tag A = Z85,
 *                            tag 賒 = base4096 (CJK digits, denser, IM-safe)
 *           key = HKDF-SHA256(X25519(eph, recip), salt=ephPub||recipPub,
 *                              info="ecdh.html/v1", 32)
 * Public keys are shared as hex (0-9a-f only — IM software can mangle
 * base64's alphabet into emoji). encryptTo() takes raw plaintext bytes and
 * returns raw envelope bytes; decryptWith() takes the tagged text form and
 * returns raw plaintext bytes — the text encoding is a swappable layer.
 * See README.md for the pinned threat model and byte-exact spec.
 * ===================================================================== */

/* ---------- tiny format helpers ---------- */
function b64enc(u8){
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}
function b64dec(str){
  const clean = str.replace(/\s+/g, "");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/* Z85 (ZeroMQ base85): 4 bytes -> 5 chars, 25% overhead vs base64's 33%.
 * Alphabet is ZeroMQ's: digits + letters + punctuation, chosen to avoid
 * quotes and backslash, so it survives JSON/shell/markdown channels that
 * mangle Ascii85's `"` `'` `\` range. The Z85 spec only defines lengths
 * divisible by 4; envelope lengths aren't (45 bytes + plaintext), so tails
 * follow the classic Ascii85 convention: encode zero-pads the final group
 * and emits r+1 chars for the last r bytes; decode pads a short final group
 * with the highest digit ('#') and keeps the k-1 bytes a k-char tail packs.
 * Every 5-char group must decode to a value below 2^32 — legal tails never
 * overflow that, so a bigger value marks the input as non-canonical. */
const Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const Z85_REV = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < Z85.length; i++) t[Z85.charCodeAt(i)] = i;
  return t;
})();
function z85enc(u8){
  const out = [];
  const push = (b0, b1, b2, b3, keep) => {
    let n = b0 * 16777216 + b1 * 65536 + b2 * 256 + b3;
    const digits = new Array(5);
    for (let d = 4; d >= 0; d--){ digits[d] = Z85[n % 85]; n = Math.floor(n / 85); }
    for (let d = 0; d < keep; d++) out.push(digits[d]);
  };
  let o = 0;
  for (; o + 4 <= u8.length; o += 4) push(u8[o], u8[o + 1], u8[o + 2], u8[o + 3], 5);
  const r = u8.length - o;
  if (r) push(u8[o], r > 1 ? u8[o + 1] : 0, r > 2 ? u8[o + 2] : 0, 0, r + 1);
  return out.join("");
}
function z85dec(str){
  const len = str.length;
  const rem = len % 5;
  if (rem === 1) throw new Error("A 1-char tail carries no bytes; Z85 tails are 2-4 chars.");
  const groups = (len - rem) / 5;
  const out = new Uint8Array(groups * 4 + (rem ? rem - 1 : 0));
  let o = 0;
  for (let g = 0; g < groups + (rem ? 1 : 0); g++){
    const present = g < groups ? 5 : rem;   // chars actually in this group
    let v = 0;
    for (let d = 0; d < 5; d++){
      let digit;
      if (d >= present) digit = 84;         // pad a short tail with '#'
      else {
        const c = str.charCodeAt(g * 5 + d);
        digit = c < 256 ? Z85_REV[c] : -1;
      }
      if (digit < 0) throw new Error("Character at position " + (g * 5 + d) + " is not in the Z85 alphabet.");
      v = v * 85 + digit;
    }
    if (v > 4294967295) throw new Error("Z85 group " + g + " decodes above 32 bits (non-canonical input).");
    const keep = g < groups ? 4 : rem - 1;
    for (let b = 0; b < keep; b++) out[o++] = Math.floor(v / 2 ** (8 * (3 - b))) % 256;
  }
  return out;
}
/* ---------- base4096 (tag 賒) ---------- */
/* CJK base4096: 12 bits per char — 3 bytes -> 2 chars (0.68 chars/byte, vs
 * Z85's 1.25). The digit set below is 4096 archaic hanzi from the nature and
 * object radicals of the CJK block (土山木水田石竹糸艸雨金貝車馬鳥魚…), pinned
 * here verbatim — this constant is the source of truth for the charset:
 *   - every char is in U+4E62..U+8CCF (BMP; assigned since long before
 *     Unicode 5.1, so system CJK fonts render it everywhere)
 *   - none encodes in GB2312 and none is in the 3500 常用字 / 7000 通用字
 *     lists — no common Chinese vocabulary, sensitive or otherwise, can be
 *     spelled in the output, so IM keyword filters have nothing to match;
 *     the text reads as harmless classical-looking noun soup
 *   - digits are ordered by codepoint (first digit 乢); PAD1/PAD2/TAG are the
 *     next three candidates, same visual class
 * Selection recipe (Unicode 18.0 kRSUnicode, radicals 土山木水牛田石竹糸羊羽
 * 艸虫角谷豆豕豸貝車酉里金長門阜隹雨青非面革韋韭音頁風飛食首香馬魚鳥鹿龍龜;
 * drop GB2312-encodable + 通用字表 chars; ascending codepoint; first 4096,
 * then PAD1, PAD2, TAG).
 * Tails: a 1-byte tail is one digit (byte<<4) + PAD1; a 2-byte tail is two
 * digits (16 data bits in a 24-bit slot) + PAD2. Decode reads the PAD marker
 * to size the tail and rejects any nonzero padding bits — canonical only. */
const B4096_TABLE = [
  "乢圠圡圢圤圥圦圧圫圱圲圴圵圶圷圸圼圽圿坁坃坄坅坆坈坉坋坒坓坔坕坖坘坙坢坣坥坧坬坮坰坱坲坴坵坸坹坺坽坾坿垀垁垇垈垉垊垎垏垐垑垔垕垖",
  "垗垘垙垚垜垝垥垨垪垬垰垳垵垶垷垹垺垻垼垽垾垿埀埁埄埅埆埇埈埉埊埌埍埐埑埓埖埗埛埜埞埡埢埣埥埦埧埨埩埪埫埬埮埰埱埲埳埵埶執埻埾埿堁",
  "堃堄堅堈堊堎堏堐堒堓堔堖堗堘堚堛堜堝堟堢堣堥堦堧堨堩堫堬堭堮堯報堲堳場堶堷堸堹堺堻堼堽堾堿塀塁塂塅塇塉塊塋塎塏塐塒塓塕塖塗塙塚塛",
  "塜塝塟塠塡塢塣塤塦塧塨塩塪塭塯塰塱塲塳塴塵塶塷塸塹塺塻塼塽塿墂墄墆墇墊墋墌墍墎墏墐墑墔墕墖増墘墛墜墝墠墡墢墣墤墥墧墪墫墬墭墮墯墰",
  "墱墲墳墴墵墶墷墸墹墺墻墽墾墿壀壂壃壄壆壇壈壉壊壋壌壍壎壏壐壒壓壔壖壗壘壙壚壛壜壝壞壟壠壢壣壥壦壧壨壩壪屲屳屴屵屶屷屸屻屼屽屾岀岃",
  "岄岅岆岇岉岊岋岎岏岒岓岕岝岞岟岠岡岤岥岦岧岨岪岮岯岰岲岴岶岹岺岻岼岾峀峃峅峆峇峈峉峊峌峍峎峏峐峑峓峔峕峖峗峘峚峛峜峝峞峟峠峢峩峫",
  "峬峮峯峱峲峳峴峵島峷峸峹峺峼峽峾峿崀崁崄崅崈崉崊崋崌崍崏崐崑崒崓崕崗崘崙崚崜崝崠崡崢崣崥崨崪崫崬崯崰崱崲崳崵崶崷崸崹崺崻崼崿嵀嵁",
  "嵂嵃嵄嵅嵆嵈嵉嵍嵏嵐嵑嵒嵓嵔嵕嵗嵙嵜嵞嵟嵠嵡嵢嵣嵤嵥嵦嵧嵨嵪嵭嵮嵰嵱嵲嵳嵵嵶嵷嵸嵹嵺嵻嵼嵽嵾嵿嶀嶁嶃嶄嶅嶆嶇嶈嶉嶊嶋嶌嶍嶎嶏嶐嶑",
  "嶒嶔嶕嶖嶗嶘嶚嶛嶜嶞嶟嶠嶡嶢嶣嶤嶥嶦嶧嶨嶩嶪嶫嶬嶭嶮嶯嶰嶱嶲嶳嶴嶵嶶嶸嶹嶺嶻嶼嶽嶾嶿巀巁巂巃巄巆巇巈巊巋巌巎巏巐巑巒巓巔巕巖巗巘",
  "巙巚朩朮朰朲朳朶朷朸朹朻朼朾朿杁杄杅杇杊杋杍杒杔杕杗杘杙杚杛杝杢杣杤杦杫杬杮東杴杶杸杹杺杽枀枂枃枅枆枈枊枌枍枎枏枑枒枓枔枖枙枛枟",
  "枠枡枤枦枩枬枮枱枲枴枹枺枻枼枽枾枿柀柂柅柆柇柉柊柋柌柍柎柕柖柗柛柟柡柣柤柦柧柨柪柫柭柮柲柵柶柷柸柹柺査柼柾栁栂栃栄栆栍栐栔栕栘栙",
  "栚栛栜栞栠栢栣栤栥栦栧栨栫栬栭栮栯栰栱栴栵栶栺栻栿桇桋桍桏桒桖桗桘桙桚桛桜桝桞桟桪桬桭桮桯桰桱桲桳桵桸桹桺桻桼桽桾桿梀梂梄梇梈梉",
  "梊梋梌梍梎梐梑梒梔梕梖梘梙梚梛梜條梞梟梠梡梣梤梥梩梪梫梬梮梱梲梴梶梷梸梹梺梻梼梿棃棄棅棆棇棈棊棌棎棏棐棑棓棔棖棗棙棛棜棝棞棟棡棢",
  "棤棥棦棧棩棪棫棭棯棲棳棴棶棷棸棽棾棿椀椂椃椄椆椇椈椉椊椌椏椓椔椕椖椗椘椙椚椛検椝椞椡椢椣椥椦椧椨椩椪椫椬椮椯椱椲椳椵椶椷椸椺椻椼",
  "椾楀楁楃楄楅楆楇楈楉楊楋楌楍楎楏楐楑楒楓楕楖楘楙楛楜楟楡楢楤楥楧楨楩楪楬業楰楲楳楴極楶楺楻楽楾楿榁榃榅榊榋榌榎榏榐榑榒榓榗榙榚榝",
  "榞榟榠榡榢榣榤榥榦榩榪榬榮榯榰榲榳榵榶榸榹榺榼榽榾榿槀槂槃槄槅槆槇槈槉構槍槏槑槒槓槕槖槗様槙槝槞槡槢槣槤槥槦槧槨槩槪槫槬槮槯槰槱",
  "槳槴槵槶槷槸槹槺槻槼槾樀樁樂樃樄樅樆樇樈樉樋樌樍樎樏樐樑樒樓樔樕樖標樚樛樜樝樞樠樢樣樤樥樦樧権樫樬樭樮樰樲樳樴樶樷樸樹樺樻樼樿橀",
  "橁橂橃橅橆橈橉橊橋橌橍橎橏橑橒橓橔橕橖橗橚橜橝橞機橠橢橣橤橧橨橩橪橫橬橭橮橯橰橲橳橴橵橶橷橸橺橻橽橾橿檁檂檃檅檆檇檈檉檊檋檌檍檏",
  "檒檓檔檕檖檘檙檚檛檜檝檞檟檡檢檣檤檥檦檧檨檪檭檮檯檰檱檲檳檴檶檷檸檹檺檻檼檽檾檿櫀櫁櫂櫃櫄櫅櫆櫇櫈櫉櫊櫋櫌櫍櫎櫏櫐櫑櫒櫓櫔櫕櫖櫗",
  "櫘櫙櫚櫛櫜櫝櫞櫟櫠櫡櫢櫣櫤櫥櫦櫧櫨櫩櫪櫫櫬櫭櫮櫯櫰櫱櫲櫳櫴櫵櫶櫷櫸櫹櫺櫻櫼櫽櫾櫿欀欁欂欃欄欅欆欇欈欉權欋欌欍欎欏欐欑欒欓欔欕欖欗",
  "欘欙欚欛欜欝欞欟氶氷氹氺氻氼氾氿汃汄汅汋汌汍汎汏汑汒汓汖汘汙汚汢汣汥汦汧汫汬汮汯汱汳汵汷汸決汻汼汿沀沇沊沋沍沎沑沒沕沖沗沜沝沞沠",
  "沢沬沯沰沴沵沶沷沺泀況泂泆泇泈泋泍泎泏泑泒泘泙泝泟泤泦泧泩泬泭泲泴泹泿洀洂洃洅洆洈洉洊洍洏洐洓洔洕洖洘洜洝洟洠洡洢洤洦洩洬洭洯洰",
  "洶洷洸洿浀浂浄浌浖浗浘浛浝浟浢浤浧浨浫浬浭浰浱浲浳浵浶浹浺浻浽浾浿涀涁涃涄涆涇涊涋涍涏涐涒涖涗涙涚涜涥涬涭涰涱涳涴涶涷涹涺涻涼涽",
  "涾淁淂淃淈淉淊淍淎淐淒淓淔淕淗淚淛淜淟淢淣淥淧淨淩淪淭淯淰淲淴淵淶淸淺淽淾淿渀渁渂渃渄渆渇済渉渋渏渒渓渕渘渙減渜渞渟渢渦渧渨渪測",
  "渮渰渱渳渵渶渷渹渻渼渽渾渿湀湁湂湅湆湇湈湊湋湌湏湐湑湒湕湗湙湚湞湠湡湢湣湤湥湦湧湩湪湬湭湯湰湱湳湴湵湶湷湸湹湺湻湼湽満溁溂溄溈溊",
  "溋溌溍溎溑溒溓溔溕準溗溙溚溛溝溞溡溣溤溨溩溫溬溭溮溰溳溵溸溹溼溾溿滀滄滅滆滈滉滊滌滎滐滒滖滙滛滜滝滣滧滬滭滮滯滰滱滲滳滵滶滷滸滺",
  "滻滼滽滾滿漀漁漃漄漅漇漈漊漋漌漍漎漐漑漒漖漗漘漙漚漛漜漝漞漟漡漢漣漥漦漧漨漬漮漰漲漴漵漷漸漹漺漻漼漽漿潀潁潂潃潄潅潈潉潊潌潎潐潑",
  "潒潓潔潕潖潗潙潚潛潝潠潡潣潤潥潧潨潩潪潫潬潯潰潱潳潶潷潹潻潾潿澀澁澂澃澅澆澇澊澋澏澐澑澒澓澔澕澖澗澘澙澚澛澝澞澟澠澢澣澤澦澨澩澪",
  "澫澬澭澮澯澰澱澲澵澷澸澺澻澽澾澿濁濃濄濅濆濇濈濊濋濌濍濎濏濐濓濔濕濖濗濘濙濚濛濜濝濟濢濣濤濥濦濧濨濩濪濫濬濭濰濱濲濳濴濵濶濷濸濹",
  "濺濻濼濽濾濿瀀瀁瀂瀃瀄瀅瀆瀇瀈瀉瀊瀋瀎瀏瀐瀒瀓瀔瀕瀖瀗瀘瀙瀜瀝瀞瀟瀠瀡瀢瀤瀥瀦瀧瀨瀩瀪瀫瀬瀭瀮瀯瀰瀱瀲瀳瀴瀶瀷瀸瀺瀻瀼瀽瀾瀿灀灁",
  "灂灃灄灅灆灇灈灉灊灋灍灎灐灑灒灓灔灕灖灗灘灙灚灛灜灝灟灠灡灢灣灤灥灦灧灨灩灪牜牞牠牣牤牥牨牪牫牬牭牰牱牳牴牶牷牸牻牼牽犂犃犅犆犇",
  "犈犉犌犎犐犑犓犔犕犖犗犘犙犚犛犜犝犞犠犡犢犣犤犥犦犧犩犪犫甴甶甹甼甽甿畁畂畃畄畆畇畉畊畍畐畑畒畓畕畖畗畘畝畞畟畡畢畣畤畧畩畫畬畭",
  "畮異畱畳畵當畷畺畻畼畽畾疀疁疂疄疅疇疈疉疊矴矵矷矹矺矼砃砄砅砆砇砈砊砋砎砏砐砓砕砙砛砞砠砡砢砤砨砪砫砯砱砲砳砵砶砽砿硂硃硄硆硈硉",
  "硊硋硍硏硑硓硔硘硙硛硜硞硟硠硡硢硣硤硥硦硧硨硩硯硰硱硲硳硴硵硶硸硹硺硻硽硾硿碀碁碂碃碄碅碆碈碊碋碏碐碒碔碕碖碙碝碞碠碢碤碦碨碩碪",
  "碫碬碭碮碯碵碷碸確碻碼碽碿磀磂磃磄磆磇磈磌磍磎磏磑磒磓磖磗磘磚磛磜磝磞磟磠磡磢磣磤磥磦磧磩磪磫磭磮磯磰磱磳磵磶磸磹磻磼磽磾磿礀礂",
  "礃礄礆礇礈礉礊礋礍礎礏礐礑礒礔礕礖礗礘礙礚礛礜礝礟礠礡礢礣礥礦礧礨礩礪礫礬礭礮礯礰礱礲礵礶礷礸礹竻竼竾笀笁笂笅笇笉笌笍笎笐笒笓笖",
  "笗笘笚笜笝笟笡笢笣笧笩笭笯笰笲笴笵笶笷笹笻笽笿筀筁筂筃筄筆筈筊筍筎筓筕筗筙筞筟筡筣筤筥筦筧筨筩筪筫筬筭筯筰筳筴筶筸筺筽筿箁箂箃箄",
  "箆箇箈箉箊箋箌箎箏箑箒箖箘箙箚箛箞箟箠箣箤箥箮箯箰箲箳箵箶箷箹箺箻箼箽箾箿節篂篃範篅篈築篊篋篍篎篏篐篒篔篕篖篗篘篛篜篞篟篠篢篣篤",
  "篧篨篩篫篬篭篯篰篲篳篴篵篶篸篹篺篻篽篿簀簁簂簄簅簆簈簊簍簎簐簑簒簓簔簕簗簘簙簚簛簜簝簞簡簢簣簤簥簨簩簫簬簭簮簯簰簱簲簳簴簵簶簷簹",
  "簺簻簼簽簾籂籃籄籅籆籇籈籉籊籋籌籎籏籐籑籒籓籔籕籖籗籘籙籚籛籜籝籞籟籠籡籢籣籤籥籦籧籨籩籪籫籬籭籮籯籰籱籲糹糺糼糽糾糿紀紁紂紃約",
  "紅紆紇紈紉紋紌納紎紏紐紑紒紓純紕紖紗紘紙級紛紜紝紞紟紡紣紤紥紦紨紩紪紬紭紮細紱紲紳紴紵紶紷紸紹紺紻紼紽紾紿絀絁終絃組絅絆絇絈絉絊",
  "絋経絍絎絏結絑絒絓絔絕絖絗絘絙絚絛絜絝絞絟絠絡絢絣絤絥給絧絨絩絪絫絬絭絯絰統絲絳絴絵絶絸絹絺絻絼絽絾絿綀綁綂綃綄綅綆綇綈綉綊綋綌",
  "綍綎綏綐綑綒經綔綕綖綗綘継続綛綜綝綞綟綠綡綢綣綤綥綧綨綩綪綫綬維綯綰綱網綳綴綵綶綷綸綹綺綻綼綽綾綿緀緁緂緃緄緅緆緇緈緉緊緋緌緍緎",
  "総緐緑緒緓緔緕緖緗緘緙線緛緜緝緞緟締緡緢緣緤緥緦緧編緩緪緫緬緭緮緯緰緱緲緳練緵緶緷緸緹緺緻緼緽緾緿縀縁縂縃縄縅縆縇縈縉縊縋縌縍縎",
  "縏縐縑縒縓縔縕縖縗縘縙縚縛縜縝縞縟縠縡縢縣縤縥縦縧縨縩縪縫縬縭縮縯縰縱縲縳縴縵縶縷縸縹縺縼總績縿繀繂繃繅繆繈繉繊繋繌繍繎繏繐繑繒",
  "繓織繕繖繗繘繙繚繛繜繝繞繟繠繡繢繣繤繥繦繧繨繩繪繫繬繭繮繯繰繱繲繳繴繵繶繷繸繹繺繻繼繽繾繿纀纁纃纄纅纆纇纈纉纊纋續纍纎纏纐纑纒纓",
  "纔纕纖纗纘纙纚纜纝纞纮纼绖绬缊缐缞羋羍羏羐羒羓羕羖羗羘羙羛羜羠羢羣羥羦羨義羪羫羬羭羮羱羳羴羵羶羷羺羻臤臥臦臨臩艸艻艼芀芁芃芅芆芇",
  "芉芌芐芓芔芕芖芚芛芞芠芢芣芧芲芵芶芺芻芿苀苂苃苅苆苉苐苖苙苚苝苢苧苨苩苪苬苭苮苰苲苳苵苶苸苺苼苽苾苿茊茋茍茐茒茖茘茙茞茟茠茡茢茣",
  "茤茥茦茩茪茮茰茲茷茻茽茾茿荁荂荄荅荈荊荋荌荍荎荓荕荖荗荘荝荢荰荱荲荳荴荵荶荹荺荾荿莀莁莂莃莄莇莈莊莋莌莍莏莐莑莔莕莖莗莚莝莟莡莢",
  "莣莤莥莦莧莬莭莮莯莵莻莾莿菃菄菆菈菉菋菍菎菐菑菒菓菕菗菙菚菛菞菢菣菤菦菧菨菫菬菭菮華菳菴菵菶菷菺菻菾菿萀萂萅萇萈萉萊萐萒萓萔萕萖",
  "萗萙萚萛萞萟萠萡萢萣萪萫萭萮萯萰萲萳萴萵萶萷萹萺萻萾萿葀葁葂葃葄葅葇葈葉葊葋葌葍葎葏葐葒葔葕葘葝葞葟葠葢葤葥葦葧葨葪葮葯葰葲葴葷",
  "葹葻葼葽葾葿蒀蒁蒃蒄蒅蒆蒊蒍蒏蒐蒑蒒蒓蒔蒕蒖蒘蒚蒛蒝蒞蒠蒢蒣蒤蒥蒦蒧蒨蒩蒪蒫蒬蒭蒮蒰蒱蒳蒵蒶蒷蒻蒼蒾蓀蓃蓅蓆蓈蓋蓌蓎蓏蓒蓔蓕蓗蓘",
  "蓙蓚蓛蓜蓞蓡蓢蓤蓧蓨蓩蓪蓫蓭蓮蓯蓱蓲蓳蓴蓵蓶蓷蓸蓹蓺蓻蓽蓾蔀蔁蔂蔃蔄蔅蔆蔇蔈蔉蔊蔋蔍蔎蔏蔐蔒蔔蔕蔖蔘蔙蔛蔜蔝蔞蔠蔢蔣蔤蔥蔦蔧蔨蔩",
  "蔪蔭蔮蔯蔰蔱蔲蔳蔴蔵蔶蔾蔿蕀蕁蕂蕄蕅蕆蕇蕋蕌蕍蕎蕏蕐蕑蕒蕓蕔蕕蕗蕘蕚蕛蕜蕝蕟蕠蕡蕢蕣蕥蕦蕧蕩蕪蕫蕬蕭蕮蕯蕱蕳蕵蕶蕷蕸蕼蕽蕿薀薁薂",
  "薃薆薈薉薊薋薌薍薎薐薑薒薓薔薕薖薗薘薙薚薝薞薟薠薡薢薣薥薦薧薩薫薬薭薱薲薳薴薵薶薸薺薻薼薽薾薿藀藂藃藄藅藆藇藈藊藋藌藍藎藑藒藔藖",
  "藗藘藙藚藛藝藞藟藡藢藣藥藦藧藨藪藫藬藭藮藯藰藱藲藳藴藵藶藷藸藹藺藼藽藾蘀蘁蘂蘃蘄蘆蘇蘈蘉蘊蘋蘌蘍蘎蘏蘐蘒蘓蘔蘕蘗蘙蘚蘛蘜蘝蘞蘟蘠",
  "蘡蘢蘣蘤蘥蘦蘨蘪蘫蘬蘭蘮蘯蘰蘱蘲蘳蘴蘵蘶蘷蘹蘺蘻蘽蘾蘿虀虁虂虃虄虅虆虇虈虉虊虋虌虭虯虰虲虳虴虵虶虷虸蚃蚄蚅蚆蚇蚈蚉蚎蚏蚐蚑蚒蚔蚖",
  "蚗蚘蚙蚚蚛蚞蚟蚠蚡蚢蚥蚦蚫蚭蚮蚲蚳蚷蚸蚹蚻蚼蚽蚾蚿蛁蛂蛃蛅蛈蛌蛍蛒蛓蛕蛖蛗蛚蛜蛝蛠蛡蛢蛣蛥蛦蛧蛨蛪蛫蛬蛯蛵蛶蛷蛺蛻蛼蛽蛿蜁蜄蜅蜆",
  "蜋蜌蜏蜐蜑蜔蜖蜙蜛蜝蜟蜠蜤蜦蜧蜨蜪蜫蜬蜭蜯蜰蜲蜳蜵蜶蜸蜹蜺蜼蜽蝀蝁蝂蝃蝄蝅蝆蝊蝋蝍蝏蝐蝑蝒蝔蝕蝖蝘蝚蝛蝜蝝蝞蝟蝡蝢蝦蝧蝨蝩蝪蝫蝬",
  "蝭蝯蝱蝲蝳蝵蝷蝸蝹蝺蝿螀螁螄螆螇螉螊螌螎螏螐螑螒螔螕螖螘螙螚螛螜螝螞螡螢螤螥螦螧螩螪螮螰螱螲螴螶螷螸螹螻螼螾螿蟁蟂蟃蟄蟅蟇蟈蟉蟌",
  "蟍蟎蟏蟐蟔蟕蟖蟗蟘蟙蟚蟜蟝蟞蟟蟡蟢蟣蟤蟦蟧蟨蟩蟫蟬蟭蟯蟰蟱蟲蟳蟴蟵蟶蟷蟸蟺蟻蟼蟽蟿蠀蠁蠂蠄蠅蠆蠇蠈蠉蠌蠍蠎蠏蠐蠑蠒蠔蠗蠘蠙蠚蠜蠝",
  "蠞蠟蠠蠣蠤蠥蠦蠧蠨蠩蠪蠫蠬蠭蠮蠯蠰蠱蠳蠴蠵蠶蠷蠸蠺蠻蠽蠾蠿觓觔觕觗觘觙觛觝觟觠觡觢觤觧觨觩觪觬觭觮觰觲觴觵觶觷觸觹觺觻觼觽觾觿谸",
  "谹谺谻谼谽谾谿豀豂豃豄豅豈豊豋豍豎豏豐豑豒豓豔豖豗豘豙豛豜豝豞豟豠豣豤豥豦豧豩豬豭豮豯豰豱豲豴豵豶豷豻豼豽豾豿貀貁貃貄貆貇貈貋貍",
  "貎貏貐貑貒貓貕貖貗貙貚貛貜貝貞貟負財貢貣貤貥貦貧貨販貪貫責貭貮貯貰貱貲貳貴貵貶買貸貹貺費貼貽貾貿賀賁賂賃賄賅賆資賈賉賊賋賌賍賎賏",
].join("");
const B4096_PAD1 = "賐";
const B4096_PAD2 = "賑";
const B4096_TAG = "賒";
const B4096_REV = (() => {
  const m = new Map();
  for (let i = 0; i < 4096; i++) m.set(B4096_TABLE.charCodeAt(i), i);
  return m;
})();
function b4096enc(u8){
  const out = [];
  let o = 0;
  for (; o + 3 <= u8.length; o += 3){
    const v = (u8[o] << 16) | (u8[o + 1] << 8) | u8[o + 2];
    out.push(B4096_TABLE[v >> 12], B4096_TABLE[v & 4095]);
  }
  const r = u8.length - o;
  if (r === 1){
    out.push(B4096_TABLE[u8[o] << 4], B4096_PAD1);      // 8 data bits, low 4 zero
  } else if (r === 2){
    const v = (u8[o] << 16) | (u8[o + 1] << 8);         // 16 data bits, low 8 zero
    out.push(B4096_TABLE[v >> 12], B4096_TABLE[v & 4095], B4096_PAD2);
  }
  return out.join("");
}
function b4096dec(str){
  if (!str) return new Uint8Array(0);
  let s = str, tail = 0;
  if (s.endsWith(B4096_PAD2)) { tail = 2; s = s.slice(0, -1); }
  else if (s.endsWith(B4096_PAD1)) { tail = 1; s = s.slice(0, -1); }
  if (s.length < tail || (s.length - tail) % 2 !== 0)
    throw new Error("Bad base4096 length.");
  const digit = (i) => {
    const d = B4096_REV.get(s.charCodeAt(i));
    if (d === undefined) throw new Error("Character at position " + i + " is not in the base4096 alphabet.");
    return d;
  };
  const out = new Uint8Array((s.length - tail) / 2 * 3 + tail);
  let o = 0;
  const full = (s.length - tail) / 2;
  for (let g = 0; g < full; g++){
    const v = (digit(g * 2) << 12) | digit(g * 2 + 1);
    out[o++] = (v >> 16) & 255; out[o++] = (v >> 8) & 255; out[o++] = v & 255;
  }
  if (tail === 1){
    const v = digit(s.length - 1);
    if (v & 15) throw new Error("Non-canonical base4096: tail padding bits are set.");
    out[o] = (v >> 4) & 255;
  } else if (tail === 2){
    const v = (digit(s.length - 2) << 12) | digit(s.length - 1);
    if (v & 255) throw new Error("Non-canonical base4096: tail padding bits are set.");
    out[o] = (v >> 16) & 255; out[o + 1] = (v >> 8) & 255;
  }
  return out;
}
function hex(u8){
  let s = "";
  for (const b of u8) s += b.toString(16).padStart(2, "0");
  return s;
}
function hexdec(str){
  const s = str.replace(/\s+/g, "");
  if (!/^(?:[0-9a-f]{2})+$/i.test(s)) throw new Error("Not a valid hex string.");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
/* Public keys travel between humans, so the string form is hex — 0-9a-f
 * only, nothing an IM can autocorrect into emoji. Canonical form is 64
 * lowercase chars; decoding also tolerates uppercase and IM line-wraps. */
function pubEnc(u8){ return hex(u8); }
function pubDec(str){
  const u = hexdec(str);
  if (u.length !== 32) throw new Error("Public key must be 64 hex chars (32 bytes).");
  return u;
}
function cat(...arrs){
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs){ out.set(a, o); o += a.length; }
  return out;
}
function isZero(u8){ for (const b of u8) if (b) return false; return true; }
const TE = new TextEncoder();
const TD = new TextDecoder();

/* ---------- crypto core ---------- */
const INFO = TE.encode("ecdh.html/v1");
const VER = 1;
const PBKDF2_ITER = 800000;

// DER wrappers so raw 32-byte X25519 keys go through WebCrypto untouched.
const PKCS8_X25519 = new Uint8Array(
  [0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20]);
const X25519_BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })(); // u=9

async function genKeyPair(){
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pk8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  if (pk8.length !== 48) throw new Error("Unexpected private key encoding.");
  return { priv: pk8.slice(16), pub };
}
async function importPriv(rawScalar){
  if (rawScalar.length !== 32) throw new Error("Private scalar must be exactly 32 bytes.");
  return crypto.subtle.importKey("pkcs8", cat(PKCS8_X25519, rawScalar),
    { name: "X25519" }, false, ["deriveBits"]);
}
async function importPub(raw){
  if (raw.length !== 32) throw new Error("Public key must be exactly 32 bytes.");
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, false, []);
}
async function x25519(privScalar, peerPubRaw){
  let out;
  try {
    out = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPub(peerPubRaw) },
      await importPriv(privScalar), 256));
  } catch {
    // Some backends (e.g. Chromium) reject small-order/invalid points with an
    // empty error; Firefox returns an all-zero secret instead (caught below).
    throw new Error("Key agreement failed — invalid key material (backend rejected a key, or all-zero shared secret).");
  }
  if (out.length !== 32) throw new Error("Unexpected shared secret length.");
  return out;
}
async function pubFromPriv(scalar){ return x25519(scalar, X25519_BASE); }
async function hkdf32(ikm, salt){
  const km = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: INFO }, km, 256));
}
async function sha256(bytes){
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function x25519Supported(){
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch { return false; }
}

/* ---------- messages (envelope v1) ---------- */
/* The text form of an envelope is a one-char encoding tag followed by the
 * tagged codec's rendering of the envelope bytes. The tag says how the bytes
 * are spelled and is orthogonal to the version byte (0x01) inside, which says
 * what they mean. Tags are matched strictly (case-sensitive, no untagged
 * fallback); all decoders strip whitespace first (IM line-wraps). Table:
 *   A — Z85 (ZeroMQ base85), canonical compact ASCII form
 *   賒 — base4096: 12 bits per archaic nature-radical hanzi digit — denser
 *       than Z85, and the output is all rare classical-looking characters,
 *       so no common vocabulary (sensitive or otherwise) can be spelled in it
 * The null prototype keeps pasted first-chars like "constructor" from
 * resolving to inherited properties. */
const CODECS = Object.assign(Object.create(null),
  { A: { name: "Z85", enc: z85enc, dec: z85dec },
    [B4096_TAG]: { name: "base4096", enc: b4096enc, dec: b4096dec } });
function encodeEnv(u8, tag){
  tag = tag || "A";
  const codec = CODECS[tag];
  if (!codec) throw new Error("Unknown envelope encoding tag: " + JSON.stringify(tag)
    + " — this page writes: " + Object.keys(CODECS).join(", ") + ".");
  return tag + codec.enc(u8);
}
function decodeEnv(str){
  const s = str.replace(/\s+/g, "");
  const codec = CODECS[s[0]];
  if (!codec){
    throw new Error(s
      ? "Unknown envelope encoding tag: " + JSON.stringify(s[0])
        + " — this page reads: " + Object.keys(CODECS).join(", ") + "."
      : "Envelope is empty (no encoding tag).");
  }
  try { return codec.dec(s.slice(1)); }
  catch { throw new Error("Envelope is not valid " + codec.name + "."); }
}
async function encryptTo(recipPubRaw, plaintext){
  if (!(plaintext instanceof Uint8Array))
    throw new Error("Plaintext must be raw bytes (Uint8Array) — encode text with TE.encode().");
  // Ephemeral keypair stays non-extractable inside WebCrypto: the private
  // scalar is never exported, imported, or visible to page script.
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  let ss;
  try {
    ss = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPub(recipPubRaw) }, kp.privateKey, 256));
  } catch {
    // Same small-order/invalid-point quirk as x25519() above.
    throw new Error("Key agreement failed — invalid key material (backend rejected a key, or all-zero shared secret).");
  }
  if (isZero(ss)) throw new Error("Recipient public key is invalid (zero shared secret).");
  const key = await hkdf32(ss, cat(ephPub, recipPubRaw));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 }, aes, plaintext));
  return cat(new Uint8Array([VER]), ephPub, iv, ct);
}
async function decryptWith(privScalar, ownPubRaw, envStr){
  const u = decodeEnv(envStr);
  if (u.length < 1 + 32 + 12 + 16) throw new Error("Envelope is truncated or malformed.");
  if (u[0] !== VER) throw new Error("Unknown envelope version: " + u[0] + " — this page only reads v1.");
  const ephPub = u.slice(1, 33);
  const iv = u.slice(33, 45);
  const ct = u.slice(45);
  const ss = await x25519(privScalar, ephPub);
  if (isZero(ss)) throw new Error("Envelope's sender key is invalid (zero shared secret).");
  const key = await hkdf32(ss, cat(ephPub, ownPubRaw));
  let pt;
  try {
    const aes = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
    pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, ct);
  } catch {
    throw new Error("Decryption failed — wrong key, or envelope was tampered with.");
  }
  return new Uint8Array(pt);   // raw bytes; the caller decodes the text
}

/* ---------- passphrase wrapper (storage + export use the same record) ---------- */
async function aesKeyFromPass(pass, salt, iter, usages){
  const base = await crypto.subtle.importKey("raw", TE.encode(pass), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base,
    { name: "AES-GCM", length: 256 }, false, usages);
}
async function wrapScalar(pass, scalar, iter){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await aesKeyFromPass(pass, salt, iter, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, k, scalar));
  return { salt, iv, ct };
}
async function unwrapScalar(pass, rec){
  if (rec.v !== 1 || rec.type !== "x25519-private") throw new Error("Not an ecdh.html v1 key record.");
  if (rec.kdf !== "PBKDF2-HMAC-SHA256" || rec.cipher !== "AES-256-GCM")
    throw new Error("Record uses an unsupported KDF/cipher.");
  let salt, iv, ct, iter;
  try {
    salt = b64dec(rec.salt); iv = b64dec(rec.iv); ct = b64dec(rec.ct);
    iter = rec.iter | 0;
  } catch { throw new Error("Record is corrupted (bad base64 fields)."); }
  if (salt.length !== 16 || iv.length !== 12 || ct.length !== 48 || !(iter > 0))
    throw new Error("Record is corrupted (bad field sizes).");
  let pt;
  try {
    const k = await aesKeyFromPass(pass, salt, iter, ["decrypt"]);
    pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, k, ct));
  } catch { throw new Error("Wrong passphrase or corrupted record."); }
  if (pt.length !== 32) throw new Error("Record is corrupted (bad plaintext size).");
  return pt;
}

/* Import-side validation: the spec requires the pub field, verified against
 * the private scalar. Returns the canonical record to store/export (extra
 * fields dropped, iter normalized to the integer actually used). */
async function recordFromImport(rec, scalar){
  if (!rec || typeof rec !== "object") throw new Error("Not an ecdh.html v1 key record.");
  if (typeof rec.pub !== "string") throw new Error("Record is missing the required 'pub' field.");
  const recPub = pubDec(rec.pub);   // hex; throws on anything else
  const derivedPub = await pubFromPriv(scalar);
  if (hex(recPub) !== hex(derivedPub))
    throw new Error("Record is internally inconsistent (pub does not match private key).");
  return {
    v: 1, type: "x25519-private", pub: pubEnc(derivedPub),
    kdf: rec.kdf, iter: rec.iter | 0, cipher: rec.cipher,
    salt: rec.salt, iv: rec.iv, ct: rec.ct,
  };
}

/* ---------- fingerprints: sha256 -> 72 bits -> 12 emoji ---------- */
const EMOJI = ["🍎","🍌","🐻","🐝","🚲","🐦","⛵","🎂","🐱","🌵","🐊","🌙","☕","🎲","🐬","🥚",
  "🐘","👀","🦊","🐸","🍇","🎸","🐹","🎩","🏠","🧊","🧥","🪁","🍋","🦁","🥭","🎵",
  "🐭","🌊","🐙","🦉","🐧","🍕","🐰","🚀","🐑","🐌","🌻","🐯","🌲","🦄","🎻",
  "🌋","🍉","🐋","🦓","⚓","🍺","🧲","🌽","🍯","🐍","🌴","🥑","🐛","🥨","🦇","🍁","🐢"];
async function fpOf(pubRaw){
  const d = await sha256(pubRaw);
  let v = 0n;
  for (let i = 0; i < 9; i++) v = (v << 8n) | BigInt(d[i]);
  const em = [];
  for (let i = 0; i < 12; i++){ em.push(EMOJI[Number(v & 63n)]); v >>= 6n; }
  return { emoji: em.join(" "), hexs: hex(d) };
}

/* Node export for the test harness; inert in the browser. */
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
  module.exports = { b64enc, b64dec, z85enc, z85dec,
    B4096_TABLE, B4096_PAD1, B4096_PAD2, B4096_TAG, b4096enc, b4096dec,
    hex, pubEnc, pubDec, cat, isZero, TE, TD,
    CODECS, encodeEnv, decodeEnv,
    INFO, VER, PBKDF2_ITER,
    PKCS8_X25519, X25519_BASE, EMOJI, genKeyPair, importPriv, importPub, x25519, pubFromPriv,
    hkdf32, sha256, x25519Supported, encryptTo, decryptWith, aesKeyFromPass, wrapScalar,
    unwrapScalar, recordFromImport, fpOf };
}
