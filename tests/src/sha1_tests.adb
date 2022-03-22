with AUnit.Reporter.Text;
with AUnit.Run;

with SHA1_Streams_Tests;

procedure SHA1_Tests is
   procedure Runner is new AUnit.Run.Test_Runner (SHA1_Streams_Tests.Suite);

   Reporter : AUnit.Reporter.Text.Text_Reporter;
begin
   Reporter.Set_Use_ANSI_Colors (True);
   Runner (Reporter);
end SHA1_Tests;
