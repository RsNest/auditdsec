const fs=require("fs");
function patch(file,pairs){let s=fs.readFileSync(file,"utf8");for(const [a,b] of pairs){if(!s.includes(a))throw new Error(file+" missing "+a.slice(0,60));s=s.replace(a,()=>b);}fs.writeFileSync(file,s);}
patch("deploy/installer-deploy.sh",[
 [`            "$problem" \
            "the containers were created with`,`            "The agent is running, but the panel is not reachable. $problem" \
            "the containers were created with`],
]);
patch("scripts/e2e/compose-consistency/run.sh",[
 [`code() { curl -sSk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || echo 000; }`,`code() { local c; c="$(curl -sSk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null)"; printf '%s' "\${c:-000}"; }`],
 [`page_ok() { [ "$(front)" = 200 ] && [ "$(backend)" = 200 ]; }`,`page_ok() { [ "$(front)" = 200 ] && [ "$(backend)" = 200 ]; }
backend_ok() { [ "$(backend)" = 200 ]; }`],
 [`wait_for 60 test "$(backend)" = 200`,`wait_for 60 backend_ok`],
]);
