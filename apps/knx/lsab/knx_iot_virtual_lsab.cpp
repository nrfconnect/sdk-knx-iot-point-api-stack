/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright (c) 2022-2023 Cascoda Ltd
 Copyright (c) 2024-2025 KNX Association
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

//needs to be undefined so wx widgets will not use precompiled headers when compiling with msvc
#undef WX_PRECOMP

#include <wx/wxprec.h>
#include <wx/wx.h>
#include <wx/display.h>
#include "api/oc_knx_dev.h"
#include "oc_knx.h"
#include "apps/knx/knx_iot_virtual_knx.h"
#include "oc_knx_client.h"
#include "port/dns-sd.h"
#include "port/oc_network_interface.h"
#include "port/oc_storage.h"

extern lsxb_channel_t lsxb[LSXB_NUM_CHANNELS];

class CustomDialog : public wxDialog
{
public:
  CustomDialog(const wxString& title, const wxString& text);

private:
  void OnClose(wxCommandEvent& event);
};

CustomDialog::CustomDialog(const wxString& title, const wxString& text)
  : wxDialog(NULL, wxID_ANY, title,
             wxDefaultPosition, wxDefaultSize,
             wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxMAXIMIZE_BOX)
{
  wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

  wxTextCtrl* tc = new wxTextCtrl(this, wxID_ANY, text,
                                  wxDefaultPosition, wxDefaultSize,
                                  wxTE_MULTILINE | wxTE_READONLY | wxHSCROLL);

  vbox->Add(tc, 1, wxEXPAND | wxALL, 10);

  wxButton* closeButton = new wxButton(this, wxID_OK, "Close");
  closeButton->Bind(wxEVT_BUTTON, &CustomDialog::OnClose, this);
  vbox->Add(closeButton, 0, wxALIGN_CENTER | wxALL, 10);

  SetSizer(vbox);

  // ---- Compute content-based size ----
  wxClientDC dc(this);
  dc.SetFont(tc->GetFont());

  wxArrayString lines = wxSplit(text, '\n');
  int lineHeight = dc.GetCharHeight();
  int maxWidth = 0;
  for (auto& line : lines) {
    int w, h;
    dc.GetTextExtent(line, &w, &h);
    if (w > maxWidth) maxWidth = w;
  }

  // Estimated natural size
  int width = maxWidth + 75;                // padding
  int height = (lines.size() * lineHeight) + 150; // +button space

  // ---- Cap to 80% of screen ----
  wxDisplay display(wxDisplay::GetFromWindow(this));
  wxRect screenRect = display.GetGeometry();

  int maxW = screenRect.GetWidth() * 0.8;
  int maxH = screenRect.GetHeight() * 0.8;

  width = std::min(width, maxW);
  height = std::min(height, maxH);

  // Apply and allow resizing
  SetSize(width, height);
  SetMinSize(wxSize(100, 100));  // reasonable min

  Centre();
  ShowModal();
}

void CustomDialog::OnClose(wxCommandEvent& event)
{
  EndModal(wxID_OK);
}

class MyApp : public wxApp
{
public:
  virtual bool OnInit();
};

class MyFrame : public wxFrame
{
public:
  MyFrame();

private:
  void OnListAll(wxCommandEvent& event);
  void OnProgrammingMode(wxCommandEvent& event);
  void OnSleepyMode(wxCommandEvent& event);
  void OnReset(wxCommandEvent& event);
  void OnClearTables(wxCommandEvent& event);
  void OnRestartDevice(wxCommandEvent& event);
  void OnNetworkInterfaces(wxCommandEvent& event);
  void OnExit(wxCommandEvent& event);
  void OnAbout(wxCommandEvent& event);
  void OnTimer(wxTimerEvent& event);

  void updateCheckBoxesFromLiveSOOData();
  void updateDeviceData();

  wxMenu* m_menuFile;
  wxMenu* m_menuDisplay;
  wxMenu* m_menuOptions;
  wxTimer m_timer;

  // sleepy information
  int m_sleep_counter = 0;
  int m_sleep_milliseconds = 20000;

  // non static device properties
  wxTextCtrl* m_ia_text; // text control for internal address
  wxTextCtrl* m_iid_text; // text control for installation id
  wxTextCtrl* m_pm_text; // text control for programming mode
  wxTextCtrl* m_ls_text; // text control for load state
  wxTextCtrl* m_hn_text; // text control for host name

  // channel 0
  wxCheckBox *m_LSAB_0_SOO, *m_LSAB_1_SOO;
};

#ifdef USE_CONSOLE
  wxIMPLEMENT_APP_CONSOLE(MyApp);
#else
  wxIMPLEMENT_APP(MyApp);
#endif

/**
 * @brief initialization of the application
 *
 * @return true
 * @return false
 */
bool MyApp::OnInit()
{
  // call in c-code
  app_initialize_stack("knx_iot_virtual_lsab");

  MyFrame* frame = new MyFrame();

  frame->Fit();
  frame->Show(true);
  return true;
}

/**
 * @brief Construct a new My Frame:: My Frame object
 *
 * @param serial_number
 */
MyFrame::MyFrame() : wxFrame(nullptr, wxID_ANY, "KNX virtual actuator (LSAB)")
{
  m_menuFile = new wxMenu;
  m_menuFile->Append(LIST_ALL, "List All Tables", "List all tables in one window", false);
  m_menuFile->Append(CHECK_PM, "Programming Mode", "Sets the application in programming mode", true);
  m_menuFile->Append(RESET_TABLE, "Reset (7) (Tables)", "Reset 7 (Reset to default without IA).", false);
  m_menuFile->Append(RESET, "Reset (2) (ex-factory)", "Reset 2 (Reset to default state)", false);
  m_menuFile->Append(RESTART_DEVICE, "Restart Device", "Simulate a device restart", false);
  m_menuFile->AppendSeparator();
  m_menuFile->Append(NETWORK_INTERFACES, "Network Interfaces...", "Configure network interface selection", false);
  m_menuFile->AppendSeparator();
  m_menuFile->Append(wxID_EXIT);

  // display menu
  m_menuDisplay = new wxMenu;
  m_menuDisplay->Append(CHECK_GA_DISPLAY, "GA 3-level (ETS)", "Displays as GA 3-Level or as integer",true);
  m_menuDisplay->Check(CHECK_GA_DISPLAY, true);
  m_menuDisplay->Append(CHECK_GRPID_DISPLAY, "GRPID as partial ipv6 address (ETS)", "Displays the grpid as integer", true);
  m_menuDisplay->Check(CHECK_GRPID_DISPLAY, true);
  m_menuDisplay->Append(CHECK_IID_DISPLAY, "IID as partial ipv6 address (ETS)", "Displays the iid as integer", true);
  m_menuDisplay->Check(CHECK_IID_DISPLAY, true);

  // option menu
  m_menuOptions = new wxMenu;
  m_menuOptions->Append(CHECK_SLEEPY, "Act as Sleepy Device", "Sleeps for 20 seconds", true);
  m_menuOptions->Check(CHECK_SLEEPY, false);

  // help menu
  wxMenu* menuHelp = new wxMenu;
  menuHelp->Append(wxID_ABOUT);

  // full menu bar
  wxMenuBar* menuBar = new wxMenuBar;
  menuBar->Append(m_menuFile, "&File");
  menuBar->Append(m_menuDisplay, "&Display");
  menuBar->Append(m_menuOptions, "&Options");
  menuBar->Append(menuHelp, "&Help");
  wxFrameBase::SetMenuBar(menuBar);
  wxFrameBase::CreateStatusBar();
  wxFrameBase::SetStatusText("Welcome to KNX virtual switch actuator!");

  Bind(wxEVT_MENU, &MyFrame::OnReset, this, RESET);
  Bind(wxEVT_MENU, &MyFrame::OnListAll, this, LIST_ALL);
  Bind(wxEVT_MENU, &MyFrame::OnClearTables, this, RESET_TABLE);
  Bind(wxEVT_MENU, &MyFrame::OnProgrammingMode, this, CHECK_PM);
  Bind(wxEVT_MENU, &MyFrame::OnSleepyMode, this, CHECK_SLEEPY);
  Bind(wxEVT_MENU, &MyFrame::OnReset, this, RESET);
  Bind(wxEVT_MENU, &MyFrame::OnRestartDevice, this, RESTART_DEVICE);
  Bind(wxEVT_MENU, &MyFrame::OnNetworkInterfaces, this, NETWORK_INTERFACES);
  Bind(wxEVT_MENU, &MyFrame::OnAbout, this, wxID_ABOUT);
  Bind(wxEVT_MENU, &MyFrame::OnExit, this, wxID_EXIT);

  int x_width = 100; // width of the widgets
  int x_height = 25; // height of the widgets
  int max_instances = 4; // number of channels before the rest is shown
  int row;
  int column;

  // channel 0 - actuator
  {
    row = 0;
    column = 0;

    
   new wxStaticText(this, wxID_ANY, "Ch 0 | Actuator", 
                    wxPoint(10 + column * x_width, 10 + x_height * row),
                    wxSize(x_width, x_height), wxALIGN_LEFT);


    // status
    m_LSAB_0_SOO = new wxCheckBox(this, LSAB_0_SOO, _T("Undefined"), 
                                  wxPoint(120 + column * x_width, 10 + x_height * row),
                                  wxSize(x_width, x_height), wxCHK_3STATE);
    m_LSAB_0_SOO->Set3StateValue(wxCHK_UNDETERMINED);
    m_LSAB_0_SOO->Enable(false);

  }

  // channel 1 - actuator
  {

    row = 1;
    column = 0;

    new wxStaticText(this, wxID_ANY, "Ch 1 | Actuator",
                     wxPoint(10 + column * x_width, 10 + x_height * row),
                     wxSize(x_width, x_height), wxALIGN_LEFT);

    // status
    m_LSAB_1_SOO = new wxCheckBox(this, LSAB_1_SOO, _T("Undefined"), wxPoint(120 + column * x_width, 10 + x_height * row),
                                  wxSize(x_width, x_height), wxCHK_3STATE);
    m_LSAB_1_SOO->Set3StateValue(wxCHK_UNDETERMINED);
    m_LSAB_1_SOO->Enable(false);
  }

  constexpr int width_size = 220; // size of the knx info widgets
  char text[500]; 

  // serial number 
  const oc_device_info_t* const  device = oc_core_get_device_info();
  (void)sprintf(text, "SN:\t%s", oc_string(device->serialnumber));

  wxTextCtrl* static_text0 = new wxTextCtrl(this, wxID_ANY, text, 
                                          wxPoint(10, 10 + ((max_instances + 4) * x_height)),
                                          wxSize(width_size * 2, x_height), 0);
  static_text0->SetEditable(false);

  /* QR code
    KNX:S:serial number;P:password
    where:
    KNX: is a fixed prefix
    S: means a KNX serial number follows, sn itself is encoded as
       12 upper-case hexadecimal characters
    P: means a password follows, password itself is just
       the KNX IoT Point API password;
       this works as the allowed password characters do not interfere
       with the separator characters colon and semicolon and are in the alphanumeric range.
  */
  (void)sprintf(text, "QR:\tKNX:S:%s;P:%s", oc_string(device->serialnumber), app_get_password());
  app_str_to_upper(text);

  wxTextCtrl* static_text1 = new wxTextCtrl(this, wxID_ANY, text, 
                                            wxPoint(10, 10 + ((max_instances + 5) * x_height)),
                                            wxSize(width_size * 2, x_height), 0);
  static_text1->SetEditable(false);

  // individual address, displayed data set/refreshed later
  m_ia_text = new wxTextCtrl(this, IA_TEXT, "",
                             wxPoint(10, 10 + ((max_instances + 6) * x_height)), 
                             wxSize(width_size, x_height), 0);
  m_ia_text->SetEditable(false);

  // installation id, displayed data set/refreshed later
  m_iid_text = new wxTextCtrl(this, IID_TEXT, "", 
                              wxPoint(10 + width_size, 10 + ((max_instances + 6) * x_height)),
                              wxSize(width_size, x_height), 0);
  m_iid_text->SetEditable(false);

  // programming mode, displayed data set/refreshed later
  m_pm_text = new wxTextCtrl(this, PM_TEXT, "",
                             wxPoint(10, 10 + ((max_instances + 7) * x_height)), 
                             wxSize(width_size, x_height), 0);
  m_pm_text->SetEditable(false);

  // installation id, displayed data set/refreshed later
  m_ls_text = new wxTextCtrl(this, LS_TEXT, "", 
                             wxPoint(10 + width_size, 10 + ((max_instances + 7) * 25)),
                             wxSize(width_size, 25), 0);
  m_ls_text->SetEditable(false);

  // hostname, displayed data set/refreshed later
  m_hn_text = new wxTextCtrl(this, LS_TEXT, "",
                             wxPoint(10, 10 + ((max_instances + 8) * 25)), 
                             wxSize(width_size, 25), 0);
  m_hn_text->SetEditable(false);  // SPAKE2+ pwd
  (void)sprintf(text, "PWD:\t%s", app_get_password());
  wxTextCtrl* static_text2 = new wxTextCtrl(this, LS_TEXT, text, 
                                  wxPoint(10 + width_size, 10 + ((max_instances + 5) * 25)),
                                  wxSize(width_size, 25), 0);
  static_text2->SetEditable(false);

  // update the UI
  this->updateDeviceData();
  this->updateCheckBoxesFromLiveSOOData();

  // Calculate bounding box of all children to make Window correct size
  int maxRight = 0;
  int maxBottom = 0;

  for (wxWindowList::iterator it = GetChildren().begin(); it != GetChildren().end(); ++it)
  {
      wxWindow* child = *it;
      if (child) {
          wxRect rect = child->GetRect();
          maxRight = std::max(maxRight, rect.GetRight());
          maxBottom = std::max(maxBottom, rect.GetBottom());
      }
  }

  // Add some padding (status bar, borders, etc.)
  int paddingX = 40;
  int paddingY = 60;

  // Set minimum size dynamically
  this->SetMinSize(wxSize(maxRight + paddingX, maxBottom + paddingY));
  this->SetSize(this->GetMinSize());

  // start the 1ms interval timer for UI updates and stack polls
  m_timer.Bind(wxEVT_TIMER, &MyFrame::OnTimer, this);
  m_timer.Start(1, wxTIMER_CONTINUOUS);
}

/**
 * @brief exit the application
 *
 * @param event command triggered by the framework
 */
void MyFrame::OnExit(wxCommandEvent& event)
{
  oc_main_shutdown();
  Close(true);
}

/**
 * @brief checks/unchecks the programming mode
 *
 * @param event command triggered by the menu button
 */
void MyFrame::OnProgrammingMode(wxCommandEvent& event)
{
  SetStatusText("Changing programming mode");

  bool my_val = m_menuFile->IsChecked(CHECK_PM);
  oc_device_info_t* const device = oc_core_get_device_info();
  device->pm = my_val;

  // update the UI
  this->updateDeviceData();
  // update mdns
  knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);
}

/**
 * @brief checks/unchecks the sleepy mode
 *
 * @param event command triggered by the menu button
 */
void MyFrame::OnSleepyMode(wxCommandEvent& event)
{
  SetStatusText("Changing sleepy mode");

  bool my_sleepy = m_menuOptions->IsChecked(CHECK_SLEEPY);
  const oc_device_info_t* const  device = oc_core_get_device_info();

  if (my_sleepy)
  {
    knx_service_sleep_period(20);
  }
  else
  {
    knx_service_sleep_period(0);
  }
  // update mdns
  knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);
}

/**
 * @brief update the text buttons
 * - IA
 * - Loadstate
 * - programming mode
 * - IID
 * - Hostname
 */
void MyFrame::updateDeviceData()
{

  char text[500];

  bool iid_conversion = m_menuDisplay->IsChecked(CHECK_IID_DISPLAY);

  // get the device data structure
  const oc_device_info_t* const device = oc_core_get_device_info();

  const uint16_t ia_a = device->ia >> 12;       // area
  const uint16_t ia_l = device->ia >> 8 & 0xF;  // line
  const uint16_t ia_d = device->ia & 0x00FF;    // device
  (void)sprintf(text, "IA:\t%d.%d.%d [%d]", ia_a, ia_l, ia_d, device->ia);
  m_ia_text->SetValue(text);

  (void)sprintf(text, "LSM:\t%s", oc_core_get_lsm_state_as_string(device->lsm_s));
  m_pm_text->SetValue(text);

  (void)sprintf(text, "PM:\t%s", device->pm ? "on" : "off");
  m_ls_text->SetValue(text);

  strcpy(text, "IID:\t");
  util_int2grpid_text(device->iid, text, iid_conversion);
  m_iid_text->SetValue(text);

  (void)sprintf(text, "HOST:\t%s", oc_string_checked(device->iot_hostname));
  m_hn_text->SetValue(text);

  // set in menu the programming mode to what the device has
  m_menuFile->Check(CHECK_PM, device->pm);
}

/**
 * @brief clear the tables of the device
 *
 * @param event command triggered by button in the menu
 */
void MyFrame::OnClearTables(wxCommandEvent& event)
{
  SetStatusText("Clear Tables");
  // reset the device
  oc_knx_device_storage_reset(RESET_TO_DEFAULT_WO_IA);
  // update the UI
  this->updateDeviceData();
}

/**
 * @brief reset the device
 *
 * @param event command triggered by button in the menu
 */
void MyFrame::OnReset(wxCommandEvent& event)
{
  SetStatusText("Device Reset");
  // reset the device
  oc_knx_device_storage_reset(RESET_TO_DEFAULT_STATE);
  // update the UI
  this->updateDeviceData();
}

/**
 * @brief shows all tables combined in a window
 *
 * Opens a CustomDialog and concatenates the outputs of:
 * - Group Object Table
 * - Publisher Table
 * - Recipient Table
 * - Parameter List
 * - Auth/AT Table
 *
 * Each section is separated with headers.
 *
 * @param event command triggered by the menu button
 */
void MyFrame::OnListAll(wxCommandEvent& event)
{
  const oc_device_info_t* const  device = oc_core_get_device_info();

  bool ga_conversion = m_menuDisplay->IsChecked(CHECK_GA_DISPLAY);
  bool grpid_conversion = m_menuDisplay->IsChecked(CHECK_GRPID_DISPLAY);
  bool iid_conversion = m_menuDisplay->IsChecked(CHECK_IID_DISPLAY);

  wxString all;
  all << util_dumpQRCode()     << "\n\n"
      << util_dumpDeviceIDs()  << "\n\n"
      << util_dumpLsmState()   << "\n\n"
      << util_dumpGroupObjectTable(ga_conversion) << "\n\n"
      << util_dumpPublisherTable(ga_conversion, grpid_conversion, iid_conversion)   << "\n\n"
      << util_dumpRecipientTable(ga_conversion, grpid_conversion, iid_conversion)   << "\n\n"
      << util_dumpParameterList()    << "\n\n"
      << util_dumpAuthTable(ga_conversion);

  wxString title;
  title.Printf("LSAB - All Tables - %s", oc_string(device->serialnumber));

  CustomDialog(title, all);
  SetStatusText("List All Tables");
}

/**
 * @brief shows static info about the application
 *
 * @param event command triggered by a menu button
 */
void MyFrame::OnAbout(wxCommandEvent& event)
{
  constexpr char text[] = "(c) KNX Association, 2025-05-13";
  CustomDialog("About", text);
}

/**
 * @brief update the UI on the timer ticks
 * updates:
 * - check boxes
 * - info buttons
 * - text buttons
 * does an oc_main_poll to give a tick to the stack
 * takes into account if the device is sleepy
 * e.g. then it only does a poll each 20 seconds
 * @param event triggered by a timer
 */
void MyFrame::OnTimer(wxTimerEvent& event)
{
  bool do_poll = true;

  const bool sleepy = m_menuOptions->IsChecked(CHECK_SLEEPY);

  // do whatever you want to do every millisecond here
  if (sleepy)
  {
    do_poll = false;
    m_sleep_counter++;

    if (m_sleep_counter > m_sleep_milliseconds)
    {
      // only do a poll each x (20) seconds
      do_poll = true;
      m_sleep_counter = 0;
    }
    if (oc_knx_device_in_programming_mode())
    {
      // make sure that the device is reactive in programming mode, so keep on polling
      do_poll = true;
    }
  }

  if (do_poll)
  {
    (void)oc_main_poll();
  }

  // update possible events
  this->updateCheckBoxesFromLiveSOOData();
  this->updateDeviceData();
}

/**
 * @brief update the UI e.g. check boxes in the UI
 * updates:
 * does a oc_main_poll to give a tick to the stack
 *
 * @param event triggered by a timer
 */
void MyFrame::updateCheckBoxesFromLiveSOOData()
{

  char text[200];
  bool p;

  // update check box
  p = app_retrieve_bool_variable_from_channel(0, SOO);
  m_LSAB_0_SOO->Set3StateValue(p ? wxCHK_CHECKED : wxCHK_UNCHECKED);

  // update check box text
  strcpy(text, "SOO = ");
  util_bool2text(p, text);
  m_LSAB_0_SOO->SetLabel(text);

  // update check box
  p = app_retrieve_bool_variable_from_channel(1, SOO);
  m_LSAB_1_SOO->Set3StateValue(p ? wxCHK_CHECKED : wxCHK_UNCHECKED);

  // update check box text
  strcpy(text, "SOO = ");
  util_bool2text(p, text);
  m_LSAB_1_SOO->SetLabel(text);
  
}

/**
 * @brief initiate a restart of the stack
 *
 * @param event command triggered by the gui menu
 */
void MyFrame::OnRestartDevice(wxCommandEvent& event)
{
  SetStatusText("Restarting...");

  // Use the new public API to trigger the exact same restart as the KNX stack
  oc_knx_device_restart();

  // Update the UI immediately (restart happens asynchronously)
  this->updateDeviceData();

  SetStatusText("Restart Initiated");
}

void MyFrame::OnNetworkInterfaces(wxCommandEvent& event)
{
  NetworkInterfaceDialog dialog(this);
  dialog.ShowModal();
  SetStatusText(NetworkInterfaceDialog::GetStatusMessage());
}


