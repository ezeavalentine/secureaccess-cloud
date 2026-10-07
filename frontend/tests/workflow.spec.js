import {test,expect} from '@playwright/test';
// Separate simulated clients so suite-wide logins do not exhaust one IP bucket.
// The isolated Vite/API test proxy is trusted; production rate limits stay enabled.
test.beforeEach(async({context},testInfo)=>{
 await context.setExtraHTTPHeaders({'X-Forwarded-For':`198.51.100.${testInfo.line}`});
});
async function login(page,username='alex.dev'){
 await page.goto('/');
 await page.getByRole('button',{name:username,exact:true}).click();
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Access overview'})).toBeVisible();
}
test('invalid credentials are rejected without demo authentication',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Username',{exact:true}).fill('admin.sys');
 await page.getByLabel('Password',{exact:true}).fill('invalid-password');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('alert')).toContainText('Invalid credentials');
 await expect(page.getByRole('heading',{name:'Access overview'})).toHaveCount(0);
});
test('session restores on reload and requester never calls approval queue',async({page})=>{
 const forbidden=[];
 page.on('request',r=>{if(r.url().includes('/approvals/pending'))forbidden.push(r.url());});
 await login(page);await page.reload();
 await expect(page.getByRole('heading',{name:'Access overview'})).toBeVisible();
 await expect(page.getByText('LOCAL DEMO · AWS credentials')).toBeVisible();
 expect(forbidden).toEqual([]);
 expect(await page.evaluate(()=>localStorage.getItem('secureaccess_token'))).toBeNull();
 await page.getByRole('button',{name:'Sign Out'}).click();
 await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();
 await page.reload();await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();
});
test('request, owner credential export and revocation work',async({page})=>{
 await login(page);
 await page.getByRole('button',{name:'Request JIT access',exact:true}).click();
 await expect(page.getByLabel('Account',{exact:true})).toHaveValue('123456789012');
 await expect(page.getByLabel('Role',{exact:true})).toHaveValue('JIT-Access-ReadOnly');
 await page.getByLabel('Business justification').fill('Browser verified sandbox inspection');
 await expect(page.getByText('Eligible for JIT Auto-Approval')).toBeVisible();
 await page.getByRole('button',{name:'Submit request',exact:true}).click();
 await expect(page.getByText('Request submitted.',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:/Active JIT Sessions/}).click();
 await page.getByRole('button',{name:'Credentials',exact:true}).first().click();
 await expect(page.getByText('DEMO ONLY · These values cannot access AWS.')).toBeVisible();
 await expect(page.locator('pre')).toContainText('DEMO-NOT-VALID-AWS-CREDENTIALS');
 await page.getByRole('button',{name:'Close and clear'}).click();
 await page.getByRole('button',{name:'Revoke',exact:true}).first().click();
 await expect(page.getByText('Demo session revoked.',{exact:true})).toBeVisible();
});
test('administrator provisions and deactivates users; audit verifies',async({page})=>{
 await login(page,'admin.sys');
 await page.getByRole('button',{name:'User & Policy Management'}).click();
 await page.getByRole('button',{name:'Provision user'}).click();
 await page.getByLabel('username',{exact:true}).fill('browser.dev');
 await page.getByLabel('email',{exact:true}).fill('browser.dev@example.com');
 await page.getByLabel('full name',{exact:true}).fill('Browser Developer');
 await page.getByLabel('password',{exact:true}).fill('Browser-password-123!');
 await page.getByRole('button',{name:'Create user',exact:true}).click();
 const row=page.getByRole('row').filter({hasText:'browser.dev@example.com'});
 await expect(row).toBeVisible();await row.getByRole('button',{name:'Deactivate'}).click();
 await expect(row.getByRole('button',{name:'Activate',exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Audit Trail & Compliance'}).click();
 await expect(page.getByText('VALID',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'CloudTrail',exact:true}).click();
 await expect(page.getByText('AWS CloudTrail is unavailable in demo mode')).toBeVisible();
});
test('administrator request needs two other distinct approvers',async({browser})=>{
 const requesterContext=await browser.newContext(),approverContext=await browser.newContext(),adminContext=await browser.newContext();
 const requester=await requesterContext.newPage(),approver=await approverContext.newPage(),admin=await adminContext.newPage();
 await login(requester);
 await requester.getByRole('button',{name:'Request JIT access',exact:true}).click();
 await requester.getByLabel('Account',{exact:true}).selectOption('555444333222');
 await requester.getByLabel('Role',{exact:true}).selectOption('JIT-Access-AdministratorAccess');
 await requester.getByLabel('Business justification').fill('Investigate production incident');
 await requester.getByLabel(/Ticket reference/).fill('SEC-123');
 await expect(requester.getByText('Requires 2 distinct approver(s)')).toBeVisible();
 await requester.getByRole('button',{name:'Submit request',exact:true}).click();
 await expect(requester.getByText('Request submitted.',{exact:true})).toBeVisible();
 await login(approver,'sarah.sec');await approver.getByRole('button',{name:/Approvals Inbox/}).click();
 await approver.getByRole('button',{name:'Record Approval'}).click();
 await expect(approver.getByText('Approval recorded (1/2).',{exact:true})).toBeVisible();
 await login(admin,'admin.sys');await admin.getByRole('button',{name:/Approvals Inbox/}).click();
 await admin.getByRole('button',{name:'Record Approval'}).click();
 await expect(admin.getByText('Approved; credentials issued.',{exact:true})).toBeVisible();
 await requester.getByRole('button',{name:/Active JIT Sessions/}).click();await requester.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(requester.getByRole('cell',{name:'JIT-Access-AdministratorAccess',exact:true})).toBeVisible();
 await requesterContext.close();await approverContext.close();await adminContext.close();
});

test('MFA setup requires the current password',async({page})=>{
 await login(page);
 await page.getByRole('button',{name:'Account Security',exact:true}).click();
 await page.getByLabel('Current password to set up MFA').fill('incorrect-password');
 await page.getByRole('button',{name:'Set up MFA',exact:true}).click();
 await expect(page.getByRole('alert')).toContainText('Current password is incorrect');
 await page.getByLabel('Current password to set up MFA').fill('Password123!');
 await page.getByRole('button',{name:'Set up MFA',exact:true}).click();
 await expect(page.getByText('Add this key to your authenticator app:')).toBeVisible();
 await expect(page.getByLabel('Current password to set up MFA')).toHaveCount(0);
});

test('recovered user can change their password without entering the application',async({page})=>{
 await login(page,'admin.sys');
 const headers={'X-SecureAccess-CSRF':'1'};
 const created=await page.request.post('/api/users',{headers,data:{username:'recovery.browser',email:'recovery.browser@example.com',full_name:'Recovery Browser',password:'Original-password-123!',role:'APPROVER'}});
 expect(created.ok()).toBeTruthy();
 const user=await created.json();
 const recovered=await page.request.post(`/api/users/${user.id}/recover`,{headers,data:{reason:'Verified identity for browser recovery test',temporary_password:'Temporary-password-123!'}});
 expect(recovered.ok()).toBeTruthy();
 await page.getByRole('button',{name:'Sign Out'}).click();
 await page.getByLabel('Username',{exact:true}).fill('recovery.browser');
 await page.getByLabel('Password',{exact:true}).fill('Temporary-password-123!');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Account security',exact:true})).toBeVisible();
 await expect(page.getByRole('button',{name:'Request JIT access'})).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Dashboard',exact:true})).toHaveCount(0);
 await expect(page.getByRole('alert')).toHaveCount(0);
 await page.reload();
 await expect(page.getByRole('heading',{name:'Account security',exact:true})).toBeVisible();
 await page.getByLabel('Current password',{exact:true}).fill('Temporary-password-123!');
 await page.getByLabel('New password (at least 12 characters)').fill('Changed-password-123!');
 await page.getByRole('button',{name:'Change password and sign out'}).click();
 await expect(page.getByRole('button',{name:'Sign in',exact:true})).toBeVisible();
 await page.getByLabel('Username',{exact:true}).fill('recovery.browser');
 await page.getByLabel('Password',{exact:true}).fill('Changed-password-123!');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Access overview'})).toBeVisible();
});
