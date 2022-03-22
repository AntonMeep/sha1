with AUnit.Reporter.Text;
with AUnit.Run;

with SHA1.Tests;

procedure SHA1_Tests is
   procedure Runner is new AUnit.Run.Test_Runner (SHA1.Tests.Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Reporter.Set_Use_ANSI_Colors (True);
   Runner (Reporter);
end SHA1_Tests;
